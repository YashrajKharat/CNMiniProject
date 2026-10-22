"""File-based link between the monitor (runs as root with Mininet) and the web
app (runs as a normal user). No Mininet import, so the web app can use it.

    data/status.json    written by the monitor every sample: what it sees now
    data/metrics.jsonl  one line per sample, for the charts and the report
    data/control.json   written by the web app: mode, and a fault to inject
    data/approval.json  written by the monitor: an action waiting for a yes/no
    data/approval_response.json  written by the web app: the answer

Every write goes to a temporary file and is renamed, so a reader never sees a
half-written file.
"""
import json
import os
import re
import time

from config import DATA_DIR
from collector import fix_owner

MODES = ("monitor", "approval", "auto")
FAULTS = ("link_failure", "syn_flood", "port_scan", "latency_spike", "congestion")
MAX_METRIC_LINES = 20000
REQUEST_MAX_AGE_S = 30      # a fault request older than this is ignored
STALE_AFTER_S = 20          # no status update for this long = monitor offline


def paths(data_dir=DATA_DIR):
    j = lambda n: os.path.join(data_dir, n)
    return {"status": j("status.json"), "metrics": j("metrics.jsonl"),
            "control": j("control.json"), "approval": j("approval.json"),
            "response": j("approval_response.json"), "audit": j("audit.jsonl"),
            "commands": j("commands.jsonl")}


def read_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, default=str)
    os.replace(tmp, path)
    fix_owner(path)


def tail_lines(path, n):
    """Last n lines of a text file (the files are small, so just read them)."""
    try:
        with open(path) as f:
            return f.readlines()[-n:]
    except OSError:
        return []


def read_jsonl(path, last=None):
    if last:
        lines = tail_lines(path, last)
    else:
        try:
            with open(path) as f:
                lines = f.readlines()
        except OSError:
            lines = []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


# ------------------------------------------------------------ monitor side
class MonitorChannel:
    """Everything the monitor writes and reads. One instance per run."""

    def __init__(self, data_dir=DATA_DIR, dry_run=False):
        self.p = paths(data_dir)
        self.dry_run = dry_run
        self.started = time.time()
        self._lines = None
        self.extras = None           # function returning {"net", "commands", "incident"} for the dashboard
        self.fault_since = None      # when the fault the dashboard injected started
        self.last_was_change = False

    # --- publishing
    def _extra(self):
        out = {"fault_since": self.fault_since}
        if self.extras:
            try:
                out.update(self.extras())
            except Exception:        # a reading problem must never stop the monitor
                pass
        return out

    def publish(self, sample, detection, mode, healer, fault=None, state="monitoring",
                net_state=None):
        row = {f: sample.get(f) for f in sample if f != "label"}
        epoch = time.time()
        record = dict(row, epoch=round(epoch, 3), label=detection.label,
                      abnormal=bool(detection.abnormal), score=round(float(detection.score), 4),
                      fault=fault)
        self._append_metric(record)
        write_json(self.p["status"], {
            "updated": epoch, "started": self.started, "state": state, "mode": mode,
            "dry_run": self.dry_run, "fault": fault, "last": record,
            "on_backup": healer.reroute is not None,
            "blocked": sorted(healer.blocks), "pid": os.getpid(),
            "net": net_state})

    def refresh_net(self, net_state, fault):
        """Update just the router state and fault name in the status file, so the
        dashboard shows a change within a second or two instead of at the next sample."""
        st = read_json(self.p["status"])
        if st:
            st.update(net=net_state, fault=fault)
            write_json(self.p["status"], st)

    def heartbeat(self, mode, healer, state):
        """Keep the status fresh while the monitor is busy (approval wait)."""
        st = read_json(self.p["status"], {}) or {}
        st.update(updated=time.time(), state=state, mode=mode,
                  on_backup=healer.reroute is not None, blocked=sorted(healer.blocks),
                  **self._extra())
        write_json(self.p["status"], st)

    def _append_metric(self, record):
        os.makedirs(os.path.dirname(self.p["metrics"]) or ".", exist_ok=True)
        with open(self.p["metrics"], "a") as f:
            f.write(json.dumps(record, default=str) + "\n")
        fix_owner(self.p["metrics"])
        if self._lines is None:
            with open(self.p["metrics"]) as f:
                self._lines = sum(1 for _ in f)
        else:
            self._lines += 1
        if self._lines > MAX_METRIC_LINES:
            keep = tail_lines(self.p["metrics"], MAX_METRIC_LINES // 2)
            tmp = self.p["metrics"] + ".tmp"
            with open(tmp, "w") as f:
                f.writelines(keep)
            os.replace(tmp, self.p["metrics"])
            fix_owner(self.p["metrics"])
            self._lines = len(keep)

    def log_command(self, node, cmd, rc, out, dry_run=False):
        """Every command the healer runs on a router, so the dashboard can show it.
        'change' = alters the network; 'check' = only reads or measures."""
        change = bool(re.search(r"iptables -[ID] |ip route replace|ip rule add|ip rule del", cmd))
        self.last_was_change = change
        rec = {"epoch": round(time.time(), 3), "node": node, "cmd": cmd[:300], "rc": rc,
               "out": (out or "")[:300], "kind": "change" if change else "check",
               "dry_run": dry_run}
        os.makedirs(os.path.dirname(self.p["commands"]) or ".", exist_ok=True)
        with open(self.p["commands"], "a") as f:
            f.write(json.dumps(rec) + "\n")
        fix_owner(self.p["commands"])
        self._cmd_lines = getattr(self, "_cmd_lines", 0) + 1
        if self._cmd_lines > 1000:
            keep = tail_lines(self.p["commands"], 500)
            tmp = self.p["commands"] + ".tmp"
            with open(tmp, "w") as f:
                f.writelines(keep)
            os.replace(tmp, self.p["commands"])
            fix_owner(self.p["commands"])
            self._cmd_lines = len(keep)

    def offline(self):
        st = read_json(self.p["status"])
        if st:
            st["state"], st["updated"] = "offline", time.time()
            write_json(self.p["status"], st)

    # --- commands from the web app
    def control(self):
        c = read_json(self.p["control"], {}) or {}
        return c

    def take_injection(self):
        """Return a requested fault name once, then clear the request."""
        c = self.control()
        req = c.get("inject")
        if req and req.get("scenario") in FAULTS and not req.get("taken"):
            if time.time() - req.get("requested", 0) > REQUEST_MAX_AGE_S:
                c.pop("inject", None)          # stale (an old click): never start it late
                write_json(self.p["control"], c)
                return None
            c["inject"] = dict(req, taken=True)
            write_json(self.p["control"], c)
            return req["scenario"]
        return None

    def mode(self, default):
        m = self.control().get("mode")
        return m if m in MODES else default

    def wants_stop_fault(self):
        return bool(self.control().get("stop_fault"))

    def clear_stop_fault(self):
        c = self.control()
        if c.pop("stop_fault", None) is not None:
            write_json(self.p["control"], c)

    # --- approval through the web page
    def approver(self, healer_ref, timeout=30):
        """Returns a function with the signature DecisionEngine expects."""
        def ask(action, incident, timeout=timeout):
            ident = f"{incident.id}-{int(time.time())}"
            write_json(self.p["approval"], {
                "id": ident, "incident": incident.id, "problem": incident.label,
                "what": action.describe(), "asked": time.time(),
                "expires": time.time() + timeout})
            try:
                os.remove(self.p["response"])
            except OSError:
                pass
            end = time.time() + timeout
            answer = False
            while time.time() < end:
                r = read_json(self.p["response"])
                if r and r.get("id") == ident:
                    answer = bool(r.get("approved"))
                    break
                self.heartbeat(self.mode("approval"), healer_ref(), "waiting_for_approval")
                time.sleep(0.5)
            try:
                os.remove(self.p["approval"])
            except OSError:
                pass
            return answer
        return ask


# ----------------------------------------------------------- web app side
def set_mode(mode, data_dir=DATA_DIR):
    if mode not in MODES:
        raise ValueError("bad mode")
    p = paths(data_dir)["control"]
    c = read_json(p, {}) or {}
    c["mode"] = mode
    write_json(p, c)


def request_fault(scenario, data_dir=DATA_DIR):
    if scenario not in FAULTS:
        raise ValueError("bad scenario")
    p = paths(data_dir)["control"]
    c = read_json(p, {}) or {}
    c["inject"] = {"scenario": scenario, "requested": time.time()}
    c.pop("stop_fault", None)
    write_json(p, c)


def fault_busy(data_dir=DATA_DIR):
    """Reason a new fault cannot be requested now, or None."""
    st = current_status(data_dir)
    if st.get("fault"):
        return "A fault is already running. End it first."
    req = (st.get("control") or {}).get("inject")
    if req and not req.get("taken") and time.time() - req.get("requested", 0) <= REQUEST_MAX_AGE_S:
        return "A fault was just requested. Wait for it to start."
    return None


def request_stop_fault(data_dir=DATA_DIR):
    p = paths(data_dir)["control"]
    c = read_json(p, {}) or {}
    c["stop_fault"] = True
    write_json(p, c)


def answer_approval(ident, approved, data_dir=DATA_DIR):
    p = paths(data_dir)
    pending = read_json(p["approval"])
    if not pending or pending.get("id") != ident or time.time() > pending.get("expires", 0):
        return False
    write_json(p["response"], {"id": ident, "approved": bool(approved), "at": time.time()})
    return True


def current_status(data_dir=DATA_DIR):
    st = read_json(paths(data_dir)["status"])
    if not st:
        return {"state": "offline", "never_started": True}
    if time.time() - st.get("updated", 0) > STALE_AFTER_S and st.get("state") != "offline":
        st["state"] = "offline"
    pending = read_json(paths(data_dir)["approval"])
    if pending and time.time() > pending.get("expires", 0):
        pending = None
    st["pending_approval"] = pending
    st["control"] = read_json(paths(data_dir)["control"], {}) or {}
    return st
