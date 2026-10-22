"""Decision engine: turns detections into actions, safely.

For every sample the detector labels, call  engine.process(sample, detection).
The engine

  1. waits until the same problem has been seen in `confirm_n` samples in a
     row, so one noisy sample never triggers anything;
  2. picks an action (see ACTIONS below) or decides that none is safe;
  3. acts according to the mode:
        monitor   only log what it would do
        approval  ask the administrator first
        auto      apply the action;
  4. re-measures: it takes more samples and checks that the fix helped, and
     rolls the action back if it did not;
  5. records every step in the audit log.

    problem        action
    syn_flood      block the top SYN source at its gateway router
    port_scan      block (quarantine) the scanning source
    link_failure   reroute via the backup path
    congestion     reroute only if the link is not full; if a heavy flow is
                   filling the link, moving it would only move the problem,
                   so the engine advises and takes no action
    degraded_link  the Isolation Forest says abnormal but the Random Forest
                   cannot name it (for example a slow link, which is not a
                   trained class) AND the service is hurt (loss or latency past
                   the health limits): treated like congestion, so reroute
                   unless the link is full. Verified, and rolled back if the
                   reroute does not help
    unknown        flagged abnormal, not recognised, and the service still
                   looks healthy: log only
"""
import select
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from config import (FEATURES, HEALTH_MAX_LATENCY_MS, HEALTH_MAX_LOSS_PCT,
                    LINK_CAPACITY_MBPS, SATURATION_FRACTION)
from healing import ActionNotApplicable, BlockSource, Reroute

ACTIONABLE = ("syn_flood", "port_scan", "link_failure", "congestion",
              "degraded_link")
# The models often flip between these three for one real problem (a slow or
# broken path), so they count as one streak. The incident takes the label seen
# most often in the streak.
PATH_PROBLEMS = ("link_failure", "congestion", "degraded_link")


def streak_key(label):
    return "path" if label in PATH_PROBLEMS else label
MODES = ("monitor", "approval", "auto")


@dataclass
class Incident:
    id: int
    label: str
    first_flag_at: float
    confirmed_at: float
    evidence: dict
    status: str = "open"
    action: str = ""
    detail: str = ""
    action_at: float = 0.0
    recovered_at: float = 0.0
    verify_samples: list = field(default_factory=list)


def say(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def cli_approver(action, incident, timeout=30):
    """Ask on the terminal. No answer within `timeout` seconds means no."""
    print(f"\n  APPROVAL NEEDED: {action.describe()}\n"
          f"  Problem: {incident.label}. Apply? [y/N] (auto-decline in {timeout} s) ",
          end="", flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    answer = sys.stdin.readline().strip().lower() if ready else ""
    print()
    return answer in ("y", "yes")


class DecisionEngine:
    def __init__(self, healer, audit, sample_fn, mode="auto", confirm_n=2,
                 clear_n=3, verify_n=3, verify_need=2, settle_s=1.0,
                 approver=cli_approver):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.healer, self.audit, self.sample_fn = healer, audit, sample_fn
        self.mode = mode
        self.confirm_n, self.clear_n = confirm_n, clear_n
        self.verify_n, self.verify_need = verify_n, verify_need
        self.settle_s = settle_s
        self.approver = approver
        self.incidents = []
        self.current = None          # the incident being handled (or just closed), for the dashboard
        self.on_change = None        # called whenever the stage of the current incident changes
        self.reset()

    def reset(self):
        """Forget streaks and suppression (not the incident history)."""
        self._label = None           # streak key of the problem being counted
        self._streak = []
        self._labels = []            # the label of each sample in the streak
        self._first_flag = 0.0
        self._suppressed = None      # streak key of an incident we already dealt with
        self._clear_count = 0

    # --------------------------------------------------------------- input
    def process(self, sample, detection):
        """Feed one labelled sample. Returns an Incident when one was handled."""
        now = time.time()
        label = detection.label
        # A problem the Random Forest cannot name is still a problem when users
        # are hurting. Only the service health decides, never the unknown label.
        if label == "unknown" and self._service_degraded(sample):
            label = "degraded_link"

        key = streak_key(label)
        if label in ACTIONABLE:
            if key == self._label:
                self._streak.append(sample)
                self._labels.append(label)
            else:
                self._label, self._streak, self._labels = key, [sample], [label]
                self._first_flag = now
        else:
            self._label, self._streak, self._labels = None, [], []

        # An incident we already handled stays quiet until the problem has been
        # absent for clear_n samples in a row.
        if self._suppressed is not None:
            if key == self._suppressed:
                self._clear_count = 0
            else:
                self._clear_count += 1
                if self._clear_count >= self.clear_n:
                    self._suppressed, self._clear_count = None, 0

        if (label in ACTIONABLE and key != self._suppressed
                and len(self._streak) >= self.confirm_n):
            streak, labels = self._streak, self._labels
            self._label, self._streak, self._labels = None, [], []
            counts = Counter(labels)
            # most common label; on a tie, the most recent one
            label = next(l for l in reversed(labels) if counts[l] == max(counts.values()))
            return self._handle(label, streak, now)
        return None

    # -------------------------------------------------------------- handling
    @staticmethod
    def _service_degraded(sample):
        return (float(sample["loss_pct"]) > HEALTH_MAX_LOSS_PCT
                or float(sample["latency_ms"]) > HEALTH_MAX_LATENCY_MS)

    def _evidence(self, streak):
        return {f: round(sum(float(s[f]) for s in streak) / len(streak), 3)
                for f in FEATURES}

    def _plan(self, label, streak, evidence):
        """Returns (action, None) or (None, reason it is not acting)."""
        if label in ("syn_flood", "port_scan"):
            sources = Counter(s.get("top_src_ip") for s in streak if s.get("top_src_ip"))
            if not sources:
                return None, "no source address was identified in the traffic"
            return BlockSource(sources.most_common(1)[0][0], label), None
        if label in ("congestion", "degraded_link"):
            import config
            if not getattr(config, "REROUTE_ON_CONGESTION", False):
                if evidence["throughput_mbps"] >= SATURATION_FRACTION * LINK_CAPACITY_MBPS:
                    return None, (f"the link is full of traffic "
                                  f"({evidence['throughput_mbps']:.1f} of {LINK_CAPACITY_MBPS} Mbps); "
                                  "rerouting would only move the congestion. "
                                  "Recommend rate-limiting the heaviest flow or adding capacity")
            if self.healer.reroute is not None:
                return None, "traffic is already on the backup path"
        if label in ("link_failure", "congestion", "degraded_link"):
            return Reroute(), None

        return None, f"no action is defined for '{label}'"

    def _stage(self, inc, stage, detail=""):
        """Record a step of the incident and tell the dashboard right away."""
        now = time.time()
        if self.current is None or self.current["id"] != inc.id:
            self.current = {"id": inc.id, "problem": inc.label, "action": "",
                            "first_flag_at": inc.first_flag_at, "confirmed_at": inc.confirmed_at,
                            "stages": []}
        self.current.update(stage=stage, detail=detail, action=inc.action, at=now)
        self.current["stages"].append({"stage": stage, "detail": detail, "t": round(now, 3)})
        if self.on_change:
            try:
                self.on_change()
            except Exception:          # showing progress must never break healing
                pass

    def _close(self, inc, status, detail="", suppress=True):
        inc.status, inc.detail = status, detail or inc.detail
        if suppress:
            self._suppressed, self._clear_count = streak_key(inc.label), 0
        self.audit.write("incident_closed", incident=inc.id, problem=inc.label,
                         status=status, action=inc.action, detail=inc.detail,
                         first_flag_at=round(inc.first_flag_at, 3),
                         confirmed_at=round(inc.confirmed_at, 3),
                         recovered_at=round(inc.recovered_at, 3) or None)
        return inc

    def _handle(self, label, streak, now):
        inc = Incident(id=len(self.incidents) + 1, label=label,
                       first_flag_at=self._first_flag, confirmed_at=now,
                       evidence=self._evidence(streak))
        self.incidents.append(inc)
        self.audit.write("incident_confirmed", incident=inc.id, problem=label,
                         samples=len(streak), evidence=inc.evidence, mode=self.mode)
        self._stage(inc, "confirmed", f"{label} seen in {len(streak)} samples in a row")
        say(f"INCIDENT {inc.id}: {label} confirmed after {len(streak)} samples "
            f"(loss {inc.evidence['loss_pct']:.0f}%, latency {inc.evidence['latency_ms']:.0f} ms, "
            f"{inc.evidence['pps']:.0f} pkt/s, SYN ratio {inc.evidence['syn_ratio']:.2f}, "
            f"{inc.evidence['unique_ports_max']:.0f} ports)")

        try:
            action, reason = self._plan(label, streak, inc.evidence)
        except ActionNotApplicable as e:
            action, reason = None, str(e)
        if action is None:
            say(f"  no action: {reason}")
            self._stage(inc, "no_action", reason)
            return self._close(inc, "no_action", reason)

        inc.action = action.kind
        say(f"  planned: {action.describe()}   [mode: {self.mode}"
            f"{', dry run' if self.healer.dry_run else ''}]")
        self.audit.write("action_planned", incident=inc.id, action=action.kind,
                         what=action.describe(), mode=self.mode)
        self._stage(inc, "planned", action.describe())

        if self.mode == "monitor":
            self._stage(inc, "observed", "watch-only mode: nothing was changed")
            return self._close(inc, "observed", "monitor-only mode, nothing applied")
        if self.mode == "approval":
            self._stage(inc, "awaiting_approval", action.describe())
            self.audit.write("approval_requested", incident=inc.id, what=action.describe())
            approved = self.approver(action, inc)
            self.audit.write("approval_result", incident=inc.id, approved=approved)
            if not approved:
                say("  declined by the administrator")
                self._stage(inc, "declined", "the administrator declined, nothing was changed")
                return self._close(inc, "declined", "administrator declined")
            self._stage(inc, "approved", "the administrator approved")

        inc.action_at = time.time()
        self._stage(inc, "applying", action.describe())
        ok, detail = self.healer.apply(action, inc.id)
        if not ok:
            say(f"  FAILED to apply: {detail}")
            self.healer.rollback(action, inc.id, "apply failed")
            self._stage(inc, "failed", detail)
            return self._close(inc, "failed", detail)
        if self.healer.dry_run:
            self._stage(inc, "dry_run", "dry run: the commands were only printed")
            return self._close(inc, "dry_run", "commands printed, nothing applied")
        say(f"  applied: {detail}. Verifying...")
        self._stage(inc, "applied", detail)
        return self._verify(inc, action)

    def _verify(self, inc, action):
        time.sleep(self.settle_s)
        good = bad = 0
        for i in range(1, self.verify_n + 1):
            sample, detection = self.sample_fn()
            passed = action.verify(sample, detection)
            good, bad = good + passed, bad + (not passed)
            inc.verify_samples.append(sample)
            self.audit.write("verify_sample", incident=inc.id, n=i, passed=passed,
                             label=detection.label, loss_pct=sample["loss_pct"],
                             latency_ms=sample["latency_ms"], pps=sample["pps"],
                             syn_ratio=sample["syn_ratio"])
            say(f"  verify {i}/{self.verify_n}: {'ok' if passed else 'NOT ok'} "
                f"(model says {detection.label}, loss {float(sample['loss_pct']):.0f}%, "
                f"latency {float(sample['latency_ms']):.0f} ms)")
            self._stage(inc, "verifying",
                        f"check {i} of {self.verify_n}: {'healthy' if passed else 'still bad'} "
                        f"(loss {float(sample['loss_pct']):.0f}%, latency {float(sample['latency_ms']):.0f} ms)")
            if good >= self.verify_need or bad > self.verify_n - self.verify_need:
                break
        if good >= self.verify_need:
            inc.recovered_at = time.time()
            say(f"  RESOLVED in {inc.recovered_at - inc.confirmed_at:.1f} s after confirmation")
            self._stage(inc, "resolved", f"fixed {inc.recovered_at - inc.confirmed_at:.1f} s after confirmation")
            # The fix works, so the problem should not come back; if the same
            # label does return it is a new incident and is handled as one.
            return self._close(inc, "resolved", "verified", suppress=False)
        say("  verification FAILED, rolling back")
        self._stage(inc, "rolling_back", "the fix did not help, undoing it")
        ok, detail = self.healer.rollback(action, inc.id, "verification failed")
        self._stage(inc, "rolled_back", detail)
        return self._close(inc, "rolled_back",
                           f"fix did not help; rollback: {detail}")
