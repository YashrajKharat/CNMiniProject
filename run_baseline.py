#!/usr/bin/env python3
"""Start the simulated network and record a labeled metrics CSV.

    sudo venv/bin/python run_baseline.py --minutes 15            # baseline
    sudo venv/bin/python run_baseline.py --minutes 1 --out data/test.csv
    sudo venv/bin/python run_baseline.py --cli                   # explore by hand

Remember to start Open vSwitch first in WSL:
    sudo service openvswitch-switch start
"""
import argparse
import os
import sys

from mininet.cli import CLI
from mininet.log import info, setLogLevel

import topology as T
import traffic
from collector import MetricsCollector
from config import DATA_DIR


class AneCLI(CLI):
    """Mininet CLI plus shortcuts for trying link failure by hand."""
    prompt = "ane> "

    def do_primary_down(self, _line):
        "Bring the r1-r2 primary link down (simulated link failure)"
        T.primary_link_down(self.mn)

    def do_primary_up(self, _line):
        "Bring the r1-r2 link back up and restore primary routes"
        T.primary_link_up(self.mn)
        T.use_primary(self.mn)

    def do_use_backup(self, _line):
        "Route traffic through r3 (backup path)"
        T.use_backup(self.mn)

    def do_use_primary(self, _line):
        "Route traffic through the primary r1-r2 link"
        T.use_primary(self.mn)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--minutes", type=float, default=15)
    ap.add_argument("--interval", type=float, default=5.0,
                    help="seconds between samples (default 5)")
    ap.add_argument("--label", default="normal")
    ap.add_argument("--out", default=os.path.join(DATA_DIR, "baseline.csv"))
    ap.add_argument("--no-traffic", action="store_true",
                    help="start only the web server, no client traffic")
    ap.add_argument("--cli", action="store_true",
                    help="open the Mininet CLI instead of collecting")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Run with sudo:  sudo venv/bin/python run_baseline.py")

    setLogLevel("info")
    net = T.start_network()
    procs = []
    try:
        dropped = T.check_connectivity(net)
        if dropped > 0:
            info(f"*** WARNING: {dropped:.0f}% of pings dropped\n")
        procs = traffic.start_services(net)
        if not args.no_traffic:
            procs += traffic.start_normal_traffic(net)

        if args.cli:
            AneCLI(net)
        else:
            import time
            time.sleep(2)                 # let traffic ramp up
            info(f"*** Collecting {args.minutes} min of '{args.label}' "
                 f"data -> {args.out}\n")
            rows = MetricsCollector(net, interval=args.interval).run(
                args.minutes * 60, args.label, args.out)
            info(f"*** Done: {rows} rows written to {args.out}\n")
    except KeyboardInterrupt:
        info("\n*** Interrupted, cleaning up (rows already saved are kept)\n")
    finally:
        traffic.stop_processes(procs)
        net.stop()


if __name__ == "__main__":
    main()
