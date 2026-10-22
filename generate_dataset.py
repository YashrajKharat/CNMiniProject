#!/usr/bin/env python3
"""Generate a labeled dataset by cycling through all scenarios.

    # quick smoke test (about 3 minutes)
    sudo venv/bin/python generate_dataset.py --rounds 1 --seconds 30 --out data/smoke.csv

    # full dataset (about 50 minutes: 6 rounds x 5 labels x ~100 s)
    sudo venv/bin/python generate_dataset.py --rounds 6 --seconds 90

Each round runs every scenario once in random order. Samples taken while a
scenario is active get that scenario's name as the label. Progress is saved
row by row, so Ctrl+C keeps what has been collected so far.
"""
import argparse
import os
import random
import sys
import time

from mininet.log import info, setLogLevel

import scenarios
import topology as T
import traffic
from collector import MetricsCollector
from config import DATA_DIR

# A full nmap scan of 65535 ports ends after about 80 s at the fastest rate
PORT_SCAN_MAX_S = 75


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--rounds", type=int, default=6)
    ap.add_argument("--seconds", type=float, default=90,
                    help="seconds of samples per scenario per round")
    ap.add_argument("--cooldown", type=float, default=10,
                    help="pause between scenarios, not recorded")
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--out", default=os.path.join(DATA_DIR, "dataset.csv"))
    ap.add_argument("--only", nargs="*", choices=list(scenarios.SCENARIOS),
                    help="run only these scenarios")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Run with sudo:  sudo venv/bin/python generate_dataset.py")
    if args.seconds > PORT_SCAN_MAX_S and (not args.only or "port_scan" in args.only):
        info(f"*** Note: port_scan samples are capped at {PORT_SCAN_MAX_S} s "
             "because a full nmap scan ends after about 80 s.\n")

    setLogLevel("info")
    labels = args.only or list(scenarios.SCENARIOS)
    net = T.start_network()
    procs = []
    try:
        dropped = T.check_connectivity(net)
        if dropped > 0:
            info(f"*** WARNING: {dropped:.0f}% of pings dropped\n")
        procs = traffic.start_services(net) + traffic.start_normal_traffic(net)
        time.sleep(3)

        collector = MetricsCollector(net, interval=args.interval)
        for rnd in range(1, args.rounds + 1):
            order = labels[:]
            random.shuffle(order)
            for label in order:
                info(f"\n*** Round {rnd}/{args.rounds}: {label}\n")
                secs = (min(args.seconds, PORT_SCAN_MAX_S)
                        if label == "port_scan" else args.seconds)
                with scenarios.SCENARIOS[label](net):
                    time.sleep(2)             # let the scenario ramp up
                    collector.run(secs, label, args.out)
                time.sleep(args.cooldown)
        info(f"\n*** Finished. Dataset: {args.out}\n")
    except KeyboardInterrupt:
        info("\n*** Interrupted, cleaning up (saved rows are kept)\n")
    finally:
        traffic.stop_processes(procs)
        net.stop()


if __name__ == "__main__":
    main()
