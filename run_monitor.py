#!/usr/bin/env python3
"""Continuous monitor for the web app: runs the full loop until you stop it.

    sudo venv/bin/python run_monitor.py
    sudo venv/bin/python run_monitor.py --mode approval
    sudo venv/bin/python run_monitor.py --dry-run

Start the web app in a second terminal (no sudo):
    venv/bin/python web_app.py

The monitor starts the simulated network and normal traffic, then samples every
~5 s, detects, decides and heals exactly as in Week 3. It publishes its state to
data/status.json and data/metrics.jsonl, and takes its orders (mode, "inject a
fault", approvals) from the dashboard through data/control.json. Ctrl+C stops it
and removes any block or route change it made.
"""
import argparse
import contextlib
import os
import sys
import time

from mininet.log import setLogLevel

import netstate
import scenarios
import topology as T
import traffic
from audit import AuditLog
from collector import MetricsCollector
from config import AUDIT_LOG, DATA_DIR
from control import MODES, MonitorChannel
from decision import DecisionEngine, say
from detector import Detector
from healing import DryRunExecutor, Healer, MininetExecutor

FAULT_MAX_S = 120          # a dashboard-injected fault is removed after this long
AFTER_FIX_S = 15           # how long to keep the fault after the incident closes


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--mode", choices=MODES, default="auto",
                    help="starting mode; the dashboard can change it later")
    ap.add_argument("--dry-run", action="store_true", help="print commands, change nothing")
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--confirm", type=int, default=2)
    ap.add_argument("--block-ttl", type=int, default=600)
    ap.add_argument("--data-dir", default=DATA_DIR)
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Run with sudo:  sudo venv/bin/python run_monitor.py")
    try:
        detector = Detector()
    except FileNotFoundError as e:
        sys.exit(str(e))

    setLogLevel("warning")
    net = T.start_network()
    procs, healer, chan, stack = [], None, None, None
    try:
        dropped = T.check_connectivity(net)
        if dropped > 0:
            say(f"WARNING: {dropped:.0f}% of pings dropped before starting")
        procs = traffic.start_services(net) + traffic.start_normal_traffic(net)
        time.sleep(3)

        collector = MetricsCollector(net, interval=args.interval)
        audit = AuditLog(os.path.join(args.data_dir, "audit.jsonl")
                         if args.data_dir != DATA_DIR else AUDIT_LOG)
        chan = MonitorChannel(args.data_dir, dry_run=args.dry_run)
        reader = MininetExecutor(net)            # unlogged: only reads router state
        read_net = lambda: netstate.snapshot(reader.run)
        live = {"fault": None}

        def log_cmd(node, cmd, rc, out):
            chan.log_command(node, cmd, rc, out, args.dry_run)
            # a command that changed the network: show the new real state at once
            if chan.last_was_change:
                chan.refresh_net(read_net(), live["fault"])
        executor = (DryRunExecutor(on_run=log_cmd) if args.dry_run
                    else MininetExecutor(net, on_run=log_cmd))
        healer = Healer(executor, audit, block_ttl=args.block_ttl)

        def sample_fn():
            """One sample. It is published here, so the dashboard also sees the
            samples taken while a fix is being verified."""
            row = collector.sample("live")
            det = detector.classify(row)
            chan.publish(row, det, engine.mode, healer, fault=live["fault"],
                         net_state=read_net())
            return row, det

        engine = DecisionEngine(healer, audit, sample_fn, mode=args.mode,
                                confirm_n=args.confirm, approver=chan.approver(lambda: healer))
        audit.write("session_start", mode=args.mode, dry_run=args.dry_run, scenario="live monitor")
        say(f"monitoring. mode: {args.mode}{' (dry run)' if args.dry_run else ''}. "
            "Open the dashboard to watch and control it. Ctrl+C to stop.")

        fault, fault_t0, closed_at = None, 0.0, None
        while True:
            engine.mode = chan.mode(engine.mode)

            # a fault requested from the dashboard
            if fault is None:
                name = chan.take_injection()
                if name:
                    stack = contextlib.ExitStack()
                    stack.enter_context(scenarios.DEMO_SCENARIOS[name](net))
                    fault, fault_t0, closed_at = name, time.time(), None
                    chan.fault_since = fault_t0
                    live["fault"] = name
                    chan.refresh_net(read_net(), name)
                    engine.reset()
                    audit.write("fault_injected", scenario=name, epoch=round(fault_t0, 3),
                                source="dashboard")
                    say(f"fault injected from the dashboard: {name}")

            sample, det = sample_fn()
            incident = engine.process(sample, det)
            healer.tick()

            if fault is not None:
                if incident is not None and closed_at is None:
                    closed_at = time.time()
                stop = (chan.wants_stop_fault()
                        or time.time() - fault_t0 > FAULT_MAX_S
                        or (closed_at is not None and time.time() - closed_at > AFTER_FIX_S))
                if stop:
                    stack.close()
                    healer.cleanup()
                    chan.clear_stop_fault()
                    audit.write("fault_removed", scenario=fault)
                    say(f"fault removed: {fault}")
                    fault, stack = None, None
                    live["fault"] = None
                    chan.refresh_net(read_net(), None)
                    engine.reset()
    except KeyboardInterrupt:
        say("stopping, cleaning up")
    finally:
        with contextlib.suppress(Exception):
            if stack:
                stack.close()
        if healer is not None:
            healer.cleanup()
        if chan is not None:
            chan.offline()
        traffic.stop_processes(procs)
        net.stop()


if __name__ == "__main__":
    main()
