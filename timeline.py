"""The story of the latest fault, built from the audit and metrics logs:
fault started -> models flag it -> confirmed -> fix chosen -> applied -> verified.
No Mininet or Flask import."""
import time

from control import paths, read_jsonl


def build(data_dir):
    p = paths(data_dir)
    audit = read_jsonl(p["audit"], last=1500)
    faults = [r for r in audit if r.get("event") == "fault_injected"]
    if not faults:
        return {"fault": None, "steps": [], "outcome": None}
    f = faults[-1]
    t0 = f["epoch"]
    ev = [r for r in audit if r.get("epoch", 0) >= t0]

    def first(name):
        return next((r for r in ev if r["event"] == name), None)

    removed = first("fault_removed")
    confirmed, planned = first("incident_confirmed"), first("action_planned")
    asked, answered = first("approval_requested"), first("approval_result")
    applied, closed = first("action_applied"), first("incident_closed")
    rolled = first("rollback")
    metrics = read_jsonl(p["metrics"], last=600)
    flagged = next((m for m in metrics if m.get("epoch", 0) >= t0 and m.get("abnormal")), None)
    verifies = [r for r in ev if r["event"] == "verify_sample"
                and (confirmed is None or r.get("incident") == confirmed.get("incident"))]
    good = sum(1 for r in verifies if r.get("passed"))

    def at(rec, key="epoch"):
        return round(rec[key] - t0, 1) if rec and rec.get(key) else None

    status = closed.get("status") if closed else None
    outcome = {"resolved": "resolved", "rolled_back": "rolled back", "no_action": "advice only",
               "declined": "declined", "observed": "watch only", "failed": "failed",
               "dry_run": "dry run"}.get(status)

    if planned is None:
        fix = {"done": False, "detail": "", "t": None}
    else:
        detail = planned.get("what", "")
        if asked and answered:
            detail += " (approved)" if answered.get("approved") else " (declined)"
        elif asked:
            detail += " (waiting for your approval)"
        fix = {"done": True, "detail": detail, "t": at(planned)}

    steps = [
        {"key": "fault", "label": "Fault starts", "done": True, "t": 0.0,
         "detail": f.get("scenario", "").replace("_", " ")},
        {"key": "flag", "label": "Models flag it", "done": flagged is not None,
         "t": at(flagged), "detail": "first abnormal sample" if flagged else ""},
        {"key": "confirm", "label": "Problem confirmed", "done": confirmed is not None,
         "t": at(confirmed), "detail": (confirmed or {}).get("problem", "").replace("_", " ")
         + (" seen in 2 samples in a row" if confirmed else "")},
        dict(key="plan", label="Fix chosen", **fix),
        {"key": "apply", "label": "Fix applied on the routers", "done": applied is not None,
         "t": at(applied), "detail": (applied or {}).get("detail", "") if applied else
         ("not applied" if closed and status in ("no_action", "declined", "observed") else "")},
        {"key": "verify", "label": "Fix verified", "done": closed is not None,
         "t": at(closed) if closed else None,
         "detail": (f"{good} of {len(verifies)} checks healthy" if verifies else "")
         + (f", {outcome}" if outcome and verifies else (outcome or ""))},
    ]
    if rolled:
        steps[-1]["detail"] += " (fix undone)"
    return {"fault": f.get("scenario"), "t0": t0, "now": round(time.time(), 3),
            "outcome": outcome, "removed": removed is not None, "steps": steps,
            "active": closed is None and removed is None}
