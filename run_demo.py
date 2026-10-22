#!/usr/bin/env python3
"""Live demo of the full loop: detect -> decide -> heal -> verify.

    sudo venv/bin/python run_demo.py --scenario syn_flood
    sudo venv/bin/python run_demo.py --scenario all --repeat 3
    sudo venv/bin/python run_demo.py --scenario normal --minutes 10
    sudo venv/bin/python run_demo.py --scenario link_failure --mode approval
    sudo venv/bin/python run_demo.py --scenario port_scan --dry-run
    sudo venv/bin/python run_demo.py --check

Scenarios: link_failure, syn_flood, port_scan, latency_spike, congestion,
all (runs the five in turn) and normal (no fault: counts false alarms).

Modes: monitor (log only), approval (asks you), auto (default).
Needs models/ from train_models.py. Start Open vSwitch first in WSL:
    sudo service openvswitch-switch start
"""
import argparse
import csv
import os
import sys
import time
from collections import Counter
from datetime import datetime

from mininet.log import setLogLevel

import scenarios
import topology as T
import traffic
from audit import AuditLog
from collector import MetricsCollector, fix_owner
from config import AUDIT_LOG, DATA_DIR
from decision import DecisionEngine, say
from detector import Detector
from healing import DryRunExecutor, Healer, MininetExecutor

ALL = ["link_failure", "syn_flood", "port_scan", "latency_spike", "congestion"]
EXPECTED = {"link_failure": ("link_failure",),
            "syn_flood": ("syn_flood",),
            "port_scan": ("port_scan",),
            "congestion": ("congestion",),
            # a slow link is not one of the trained classes. The models may call
            # it a path problem, or the Random Forest may fail to name it and the
            # health fallback labels it degraded_link. All lead to the reroute
            "latency_spike": ("link_failure", "congestion", "degraded_link")}
SHOW = [("latency_ms", "latency (ms)", "{:.1f}"), ("loss_pct", "loss (%)", "{:.0f}"),
        ("throughput_mbps", "throughput (Mbps)", "{:.3f}"), ("pps", "packets/s", "{:.0f}"),
        ("syn_ratio", "SYN ratio", "{:.2f}"), ("unique_ports_max", "ports probed", "{:.0f}")]
RESULT_COLUMNS = ["time", "scenario", "mode", "dry_run", "detected", "correct", "action",
                  "status", "mttd_first_s", "mttd_confirmed_s", "mttr_s", "detail"]


def mean(rows, key):
    return sum(float(r[key]) for r in rows) / len(rows) if rows else float("nan")


def print_before_after(before, during, after):
    print("\n  Metrics        before fault    during fault      after fix")
    for key, name, fmt in SHOW:
        cells = [fmt.format(mean(rows, key)) if rows else "-" for rows in (before, during, after)]
        print(f"  {name:<18}{cells[0]:>10}{cells[1]:>16}{cells[2]:>15}")
    print()


def fmt_s(v):
    return "-" if v is None else f"{v:.1f}"


def run_scenario(name, net, sample_fn, engine, healer, args):
    engine.reset()
    n_start = len(engine.incidents)
    say(f"===== scenario: {name} =====")
    before = []
    for _ in range(args.warmup):
        row, det = sample_fn()
        before.append(row)
        engine.process(row, det)
    false_alarms = len(engine.incidents) - n_start
    if false_alarms:
        say(f"note: {false_alarms} incident(s) were raised on normal traffic")

    incident, during, after = None, [], []
    seen = Counter()          # what the models called each sample during the fault
    t0 = time.time()
    with scenarios.DEMO_SCENARIOS[name](net):
        engine.audit.write("fault_injected", scenario=name, epoch=round(t0, 3))
        say(f"fault injected: {name}")
        while time.time() - t0 < args.timeout:
            row, det = sample_fn()
            seen[det.label] += 1
            if det.abnormal and not during:
                during = [row]
            incident = engine.process(row, det)
            healer.tick()
            if incident is not None:
                break
        if incident is not None and incident.status == "resolved":
            say("collecting 'after fix' metrics while the fault is still active")
            after = [sample_fn()[0] for _ in range(args.after_samples)]
    say("model labels during the fault: "
        + ", ".join(f"{label} x{n}" for label, n in seen.most_common()))
    if incident is None:
        say(f"no incident was raised within {args.timeout} s")
    healer.cleanup()
    print_before_after(before, during or [row], after)

    res = {"time": datetime.now().isoformat(timespec="seconds"), "scenario": name,
           "mode": args.mode, "dry_run": args.dry_run, "detected": "none", "correct": False,
           "action": "", "status": "no_incident", "mttd_first_s": None,
           "mttd_confirmed_s": None, "mttr_s": None, "detail": ""}
    if incident is not None:
        res.update(detected=incident.label, correct=incident.label in EXPECTED[name],
                   action=incident.action, status=incident.status, detail=incident.detail,
                   mttd_first_s=round(incident.first_flag_at - t0, 1),
                   mttd_confirmed_s=round(incident.confirmed_at - t0, 1))
        if incident.recovered_at:
            res["mttr_s"] = round(incident.recovered_at - t0, 1)
    return res


def settle(net, sample_fn, engine, args):
    """Let the network return to normal before the next scenario."""
    time.sleep(args.cooldown)
    for _ in range(3):
        _, det = sample_fn()
        if not det.abnormal:
            return
    say("warning: traffic still looks abnormal after the cooldown")


def run_normal(minutes, sample_fn, engine, healer):
    say(f"===== no fault: {minutes} min of normal traffic, counting false alarms =====")
    n_start, flagged, total = len(engine.incidents), 0, 0
    engine.reset()
    end = time.time() + minutes * 60
    while time.time() < end:
        row, det = sample_fn()
        total += 1
        flagged += det.abnormal
        engine.process(row, det)
        healer.tick()
    acted = [i for i in engine.incidents[n_start:] if i.action]
    print(f"\n  samples: {total}   flagged abnormal: {flagged} "
          f"({100 * flagged / max(total, 1):.1f}%)   "
          f"incidents raised: {len(engine.incidents) - n_start}   "
          f"actions planned: {len(acted)}\n")


def summarize(results):
    print("\n" + "=" * 94)
    print(f"{'scenario':<15}{'detected':<14}{'ok':<5}{'action':<14}{'status':<12}"
          f"{'MTTD 1st':>9}{'MTTD conf':>10}{'MTTR':>8}")
    for r in results:
        print(f"{r['scenario']:<15}{r['detected']:<14}{'yes' if r['correct'] else 'NO':<5}"
              f"{r['action'] or '-':<14}{r['status']:<12}"
              f"{fmt_s(r['mttd_first_s']):>9}{fmt_s(r['mttd_confirmed_s']):>10}"
              f"{fmt_s(r['mttr_s']):>8}")
    print("(seconds from the moment the fault started. MTTD 1st = first abnormal sample, "
          "MTTD conf = confirmed and acted on)")
    done = [r for r in results if r["mttr_s"] is not None]
    if len(done) > 1:
        print(f"Resolved {len(done)} of {len(results)} runs; mean MTTD (confirmed) "
              f"{sum(r['mttd_confirmed_s'] for r in done) / len(done):.1f} s, "
              f"mean MTTR {sum(r['mttr_s'] for r in done) / len(done):.1f} s")


def check_environment(net, detector):
    ex = MininetExecutor(net)
    print("\nEnvironment check")
    print(f"  models loaded: yes (Isolation Forest threshold {detector.threshold:.4f})")
    rc, _ = ex.run("r1", "iptables -S FORWARD")
    print(f"  iptables on routers: {'works' if rc == 0 else 'NOT available -> will use ip rule blackhole'}")
    rc, out = ex.run("r1", "tc qdisc show dev r1-eth1")
    print(f"  traffic control on primary link: {'netem present' if 'netem' in out else 'no netem (latency_spike will squeeze the link instead)'}")
    rc, out = ex.run("r1", "ip route show 10.0.2.0/24")
    print(f"  r1 route to LAN2: {out or 'none'}")
    rc, out = ex.run("h1", "ping -c 2 -W 1 -q 10.0.2.100")
    print(f"  h1 -> web: {'reachable' if rc == 0 else 'NOT reachable'}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--scenario", default="syn_flood",
                    choices=list(scenarios.DEMO_SCENARIOS) + ["all", "normal"])
    ap.add_argument("--mode", choices=["monitor", "approval", "auto"], default="auto")
    ap.add_argument("--dry-run", action="store_true", help="print commands, change nothing")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--minutes", type=float, default=10, help="length of the 'normal' run")
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--confirm", type=int, default=2,
                    help="consecutive samples needed before acting (default 2)")
    ap.add_argument("--timeout", type=float, default=90,
                    help="give up waiting for an incident after this many seconds")
    ap.add_argument("--warmup", type=int, default=3, help="normal samples before the fault")
    ap.add_argument("--after-samples", type=int, default=2)
    ap.add_argument("--cooldown", type=float, default=10)
    ap.add_argument("--block-ttl", type=int, default=600,
                    help="seconds before a block expires on its own (0 = never)")
    ap.add_argument("--audit", default=AUDIT_LOG)
    ap.add_argument("--out", default=os.path.join(DATA_DIR, "demo_results.csv"))
    ap.add_argument("--check", action="store_true", help="check the environment and exit")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Run with sudo:  sudo venv/bin/python run_demo.py")
    try:
        detector = Detector()
    except FileNotFoundError as e:
        sys.exit(str(e))

    setLogLevel("warning")
    net = T.start_network()
    procs, healer = [], None
    results = []
    try:
        dropped = T.check_connectivity(net)
        if dropped > 0:
            say(f"WARNING: {dropped:.0f}% of pings dropped before starting")
        if args.check:
            check_environment(net, detector)
            return
        procs = traffic.start_services(net) + traffic.start_normal_traffic(net)
        time.sleep(3)

        collector = MetricsCollector(net, interval=args.interval)
        audit = AuditLog(args.audit)
        executor = DryRunExecutor() if args.dry_run else MininetExecutor(net)
        healer = Healer(executor, audit, block_ttl=args.block_ttl)

        def sample_fn():
            row = collector.sample("live")
            return row, detector.classify(row)

        engine = DecisionEngine(healer, audit, sample_fn, mode=args.mode,
                                confirm_n=args.confirm)
        audit.write("session_start", mode=args.mode, dry_run=args.dry_run,
                    scenario=args.scenario)
        say(f"mode: {args.mode}{' (dry run)' if args.dry_run else ''}. Audit log: {args.audit}")

        if args.scenario == "normal":
            run_normal(args.minutes, sample_fn, engine, healer)
        else:
            todo = (ALL if args.scenario == "all" else [args.scenario]) * args.repeat
            for i, name in enumerate(todo):
                results.append(run_scenario(name, net, sample_fn, engine, healer, args))
                if i < len(todo) - 1:
                    settle(net, sample_fn, engine, args)
            summarize(results)
            os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
            new = not os.path.exists(args.out)
            with open(args.out, "a", newline="") as f:
                w = csv.DictWriter(f, fieldnames=RESULT_COLUMNS)
                if new:
                    w.writeheader()
                w.writerows(results)
            fix_owner(args.out)
            fix_owner(os.path.dirname(args.out) or ".")
            say(f"results appended to {args.out}")
    except KeyboardInterrupt:
        say("interrupted, cleaning up")
    finally:
        if healer is not None:
            healer.cleanup()
        traffic.stop_processes(procs)
        net.stop()


if __name__ == "__main__":
    main()
