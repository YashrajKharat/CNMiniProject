"""Builds the periodic report from the audit log and the metrics log.

No Mininet or Flask import. build_report() returns a plain dict; render_html()
and render_pdf() turn it into files.
"""
import html
import os
from collections import Counter
from datetime import datetime

from config import HEALTH_MAX_LATENCY_MS, HEALTH_MAX_LOSS_PCT
from control import paths, read_json, read_jsonl, write_json


def get_tz(data_dir):
    """The administrator's time zone (remembered from their browser), else None
    (= this computer's own zone)."""
    from zoneinfo import ZoneInfo
    name = (read_json(os.path.join(data_dir, "settings.json"), {}) or {}).get("timezone")
    try:
        return ZoneInfo(name) if name else None
    except Exception:
        return None


def remember_tz(data_dir, name):
    """Save a valid IANA zone name (for example Asia/Kolkata). Returns True if valid."""
    from zoneinfo import ZoneInfo
    try:
        ZoneInfo(name)
    except Exception:
        return False
    cur = read_json(os.path.join(data_dir, "settings.json"), {}) or {}
    if cur.get("timezone") != name:
        cur["timezone"] = name
        write_json(os.path.join(data_dir, "settings.json"), cur)
    return True


def _t(epoch, tz=None):
    return datetime.fromtimestamp(epoch, tz).strftime("%Y-%m-%d %H:%M:%S")


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def build_report(data_dir, since=None, until=None, tz=None):
    p = paths(data_dir)
    tz = tz or get_tz(data_dir)
    until = until or datetime.now().timestamp()
    # +1 s: log times are rounded to the millisecond and may sit just after "now"
    audit = [r for r in read_jsonl(p["audit"]) if (since or 0) <= r.get("epoch", 0) <= until + 1]
    metrics = [r for r in read_jsonl(p["metrics"]) if (since or 0) <= r.get("epoch", 0) <= until + 1]
    if since is None:
        stamps = [r["epoch"] for r in audit + metrics if "epoch" in r]
        since = min(stamps) if stamps else until

    # --- availability: share of samples where the service was healthy
    good = [m for m in metrics
            if float(m.get("loss_pct", 0)) <= HEALTH_MAX_LOSS_PCT
            and float(m.get("latency_ms", 0)) <= HEALTH_MAX_LATENCY_MS]
    uptime = 100.0 * len(good) / len(metrics) if metrics else None
    flagged = sum(1 for m in metrics if m.get("abnormal"))
    normal_flagged = sum(1 for m in metrics if m.get("abnormal") and not m.get("fault"))
    normal_total = sum(1 for m in metrics if not m.get("fault"))

    # --- incidents: join confirmed + closed, and the fault that caused them
    confirmed = {r["incident"]: r for r in audit if r["event"] == "incident_confirmed"}
    faults = [r for r in audit if r["event"] == "fault_injected"]
    incidents = []
    for r in audit:
        if r["event"] != "incident_closed":
            continue
        c = confirmed.get(r["incident"], {})
        fault_t = None
        for f in faults:   # the latest fault that started before this incident
            if f["epoch"] <= (r.get("first_flag_at") or 0) + 0.5:
                fault_t = f["epoch"]
        first, conf, rec = r.get("first_flag_at"), r.get("confirmed_at"), r.get("recovered_at")
        incidents.append({
            "id": r["incident"], "problem": r["problem"], "status": r["status"],
            "action": r.get("action") or "", "detail": r.get("detail") or "",
            "time": _t(conf or r["epoch"], tz), "epoch": conf or r["epoch"],
            "mttd": round(conf - fault_t, 1) if fault_t and conf else None,
            "mttr": round(rec - fault_t, 1) if fault_t and rec else None,
            "evidence": c.get("evidence", {}), "mode": c.get("mode", "")})
    # the monitor numbers incidents from 1 on every start, so number them again
    # here, in time order, to keep the numbers unique inside one report
    incidents.sort(key=lambda i: i["epoch"])
    for n, inc in enumerate(incidents, 1):
        inc["id"] = n
    status_counts = Counter(i["status"] for i in incidents)
    problem_counts = Counter(i["problem"] for i in incidents)

    applied = [r for r in audit if r["event"] in ("action_applied", "action_rolled_back", "action_released")]
    rollbacks = [r for r in audit if r["event"] == "action_rolled_back"]
    blocked = Counter()
    for r in audit:
        if r["event"] == "action_applied" and "block" in str(r.get("action", "")):
            blocked[str(r.get("what", r.get("target", "")))] += 1

    rep = {
        "generated": _t(until, tz), "since": _t(since, tz), "until": _t(until, tz),
        "tz": datetime.fromtimestamp(until, tz).strftime("%Z"),
        "samples": len(metrics), "uptime_pct": uptime, "flagged": flagged,
        "false_alarm_pct": (100.0 * normal_flagged / normal_total) if normal_total else None,
        "incidents": incidents, "status_counts": dict(status_counts),
        "problem_counts": dict(problem_counts),
        "mean_mttd": _mean([i["mttd"] for i in incidents]),
        "mean_mttr": _mean([i["mttr"] for i in incidents]),
        "actions": len(applied), "rollbacks": len(rollbacks),
        "mean_latency": _mean([float(m["latency_ms"]) for m in metrics if "latency_ms" in m]),
        "peak_latency": max([float(m["latency_ms"]) for m in metrics if "latency_ms" in m], default=None),
        "audit_tail": [{"time": _t(r["epoch"], tz), "event": r["event"],
                        "text": r.get("what") or r.get("detail") or r.get("problem") or r.get("scenario") or ""}
                       for r in audit if r["event"] not in ("verify_sample", "session_start")][-25:],
    }
    rep["recommendations"] = recommendations(rep, blocked)
    return rep


def recommendations(rep, blocked):
    out = []
    pc, sc = rep["problem_counts"], rep["status_counts"]
    if not rep["incidents"]:
        out.append("No incidents in this period. No action needed.")
    if pc.get("syn_flood", 0) + pc.get("port_scan", 0) >= 2:
        out.append("Attacks came repeatedly. Blocks expire after 10 minutes, so add a permanent "
                   "firewall rule or rate limit for the offending sources at the gateway router, "
                   "and check the affected hosts for compromise.")
    if pc.get("link_failure", 0) + pc.get("degraded_link", 0) >= 1:
        out.append("Traffic was moved to the backup path at least once. The backup is slower, "
                   "so repair or replace the primary link, then confirm traffic returned to it.")
    if sc.get("no_action", 0):
        out.append("Some incidents needed a human (for example a full link). Check the audit "
                   "trail for 'no_action' and add capacity or rate-limit the heaviest flow.")
    if rep["rollbacks"] or sc.get("rolled_back", 0):
        out.append("A fix was rolled back because it did not help. Investigate those incidents "
                   "by hand: the automatic action was not the right one.")
    if sc.get("declined", 0):
        out.append("Actions were declined in approval mode. If you always approve, consider auto mode.")
    if rep["false_alarm_pct"] is not None and rep["false_alarm_pct"] > 5:
        out.append(f"{rep['false_alarm_pct']:.1f}% of normal samples were flagged. Retrain the "
                   "Isolation Forest on a longer baseline to cut false alarms.")
    if rep["uptime_pct"] is not None and rep["uptime_pct"] < 95:
        out.append(f"Service availability was {rep['uptime_pct']:.1f}%. Review the incidents above.")
    return out


# --------------------------------------------------------------- rendering
def _f(v, unit="", nd=1):
    return "n/a" if v is None else f"{v:.{nd}f}{unit}"


def render_html(rep):
    e = html.escape
    rows = "".join(
        f"<tr><td>{i['id']}</td><td>{e(i['time'])}</td><td>{e(i['problem'])}</td>"
        f"<td>{e(i['action'] or '-')}</td><td>{e(i['status'])}</td>"
        f"<td>{_f(i['mttd'], ' s')}</td><td>{_f(i['mttr'], ' s')}</td></tr>" for i in rep["incidents"]
    ) or "<tr><td colspan=7>No incidents in this period.</td></tr>"
    recs = "".join(f"<li>{e(r)}</li>" for r in rep["recommendations"])
    log = "".join(f"<tr><td>{e(a['time'][11:19])}</td><td>{e(a['event'])}</td><td>{e(str(a['text']))}</td></tr>"
                  for a in rep["audit_tail"]) or "<tr><td colspan=3>Nothing logged.</td></tr>"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Network report {e(rep['generated'])}</title><style>
body{{font-family:Arial,sans-serif;max-width:900px;margin:2em auto;color:#111;padding:0 1em}}
h1{{color:#1F3864}}h2{{color:#2E5597;margin-top:1.6em}}
table{{border-collapse:collapse;width:100%;font-size:14px}}th{{background:#1F3864;color:#fff;text-align:left}}
td,th{{border:1px solid #bbb;padding:5px 8px}}.cards{{display:flex;gap:12px;flex-wrap:wrap}}
.card{{border:1px solid #ccc;border-radius:6px;padding:10px 14px;min-width:120px}}.card b{{display:block;font-size:22px}}
@media print{{body{{margin:0}}}}</style></head><body>
<h1>Autonomous Network Engineer: Report</h1>
<p>Period {e(rep['since'])} to {e(rep['until'])} ({e(rep['tz'])}). Generated {e(rep['generated'])}.</p>
<div class="cards">
<div class="card">Availability<b>{_f(rep['uptime_pct'], '%')}</b></div>
<div class="card">Incidents<b>{len(rep['incidents'])}</b></div>
<div class="card">Mean time to detect<b>{_f(rep['mean_mttd'], ' s')}</b></div>
<div class="card">Mean time to recover<b>{_f(rep['mean_mttr'], ' s')}</b></div>
<div class="card">Rollbacks<b>{rep['rollbacks']}</b></div>
<div class="card">False alarms (no fault)<b>{_f(rep['false_alarm_pct'], '%')}</b></div></div>
<p>{rep['samples']} samples, {rep['flagged']} flagged abnormal. Mean latency {_f(rep['mean_latency'], ' ms')},
peak {_f(rep['peak_latency'], ' ms', 0)}. Availability is the share of samples with loss at most
10% and latency at most 100 ms. MTTD and MTTR are measured from a fault injected from the dashboard;
for incidents without a known start they show n/a.</p>
<h2>Incidents</h2><table><tr><th>#</th><th>Time</th><th>Problem</th><th>Action</th><th>Result</th><th>MTTD</th><th>MTTR</th></tr>{rows}</table>
<h2>Recommendations</h2><ul>{recs}</ul>
<h2>Recent actions (audit log)</h2><table><tr><th>Time</th><th>Event</th><th>Detail</th></tr>{log}</table>
</body></html>"""


def render_pdf(rep, path):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    st = getSampleStyleSheet()
    esc = html.escape
    head = TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3864")),
                       ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                       ("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 8),
                       ("VALIGN", (0, 0), (-1, -1), "TOP")])
    P = lambda t: Paragraph(esc(str(t)), st["BodyText"])
    S = lambda t: Paragraph(esc(str(t)), ParagraphStyleSmall)
    from reportlab.lib.styles import ParagraphStyle
    ParagraphStyleSmall = ParagraphStyle("s", parent=st["BodyText"], fontSize=8, leading=9.5)
    el = [Paragraph("Autonomous Network Engineer: Report", st["Title"]),
          P(f"Period {rep['since']} to {rep['until']} ({rep['tz']})"), Spacer(1, 8)]
    kp = [["Availability", "Incidents", "Mean MTTD", "Mean MTTR", "Rollbacks", "False alarms"],
          [_f(rep["uptime_pct"], "%"), len(rep["incidents"]), _f(rep["mean_mttd"], " s"),
           _f(rep["mean_mttr"], " s"), rep["rollbacks"], _f(rep["false_alarm_pct"], "%")]]
    t = Table(kp); t.setStyle(head); el += [t, Spacer(1, 6),
        P(f"{rep['samples']} samples, {rep['flagged']} flagged abnormal. Mean latency "
          f"{_f(rep['mean_latency'], ' ms')}, peak {_f(rep['peak_latency'], ' ms', 0)}.")]
    el.append(Paragraph("Incidents", st["Heading2"]))
    data = [["#", "Time", "Problem", "Action", "Result", "MTTD", "MTTR"]] + [
        [i["id"], i["time"], i["problem"], i["action"] or "-", i["status"],
         _f(i["mttd"], " s"), _f(i["mttr"], " s")] for i in rep["incidents"]]
    t = Table(data, repeatRows=1); t.setStyle(head); el.append(t)
    el.append(Paragraph("Recommendations", st["Heading2"]))
    el += [P("- " + r) for r in rep["recommendations"]]
    el.append(Paragraph("Recent actions", st["Heading2"]))
    data = [["Time", "Event", "Detail"]] + [[a["time"][11:19], a["event"], S(a["text"])] for a in rep["audit_tail"]]
    t = Table(data, repeatRows=1, colWidths=[2 * cm, 4 * cm, 11 * cm]); t.setStyle(head); el.append(t)
    SimpleDocTemplate(path, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm).build(el)


def save_report(data_dir, since=None, label="All recorded data"):
    """Write the HTML and PDF files; returns (base name, report dict).
    `label` says which period the report covers (shown in the report list)."""
    tz = get_tz(data_dir)
    rep = build_report(data_dir, since=since, tz=tz)
    out = os.path.join(data_dir, "reports")
    os.makedirs(out, exist_ok=True)
    base = "report_" + datetime.now(tz).strftime("%Y%m%d_%H%M%S")
    with open(os.path.join(out, base + ".html"), "w") as f:
        f.write(render_html(rep))
    try:
        render_pdf(rep, os.path.join(out, base + ".pdf"))
    except ImportError:
        pass
    write_json(os.path.join(out, base + ".json"), {"label": label})
    return base, rep
