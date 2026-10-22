"""Metrics collector: one feature row every few seconds.

Each sample runs two things at the same time:
  * sniff_window.py inside the web server's namespace (traffic features)
  * 5 probe pings from h1 to the web server (latency and loss)

The CSV gets one row per sample, tagged with a label ("normal" by default).
Week 2 reuses this with labels such as "syn_flood" or "port_scan".
"""
import csv
import json
import os
import re
import subprocess
import time
from datetime import datetime

from config import (COLUMNS, DATA_DIR, PING_TIMEOUT_MS, PROBE_SRC, PYTHON,
                    SNIFFER, TARGET, TARGET_IFACE, WEB_IP)

LOSS_RE = re.compile(r"([\d.]+)% packet loss")
RTT_RE = re.compile(r"min/avg/max/\w+ = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)")


def parse_ping(output):
    """Return (avg_latency_ms, loss_pct) from `ping -q` output."""
    m = LOSS_RE.search(output)
    loss = float(m.group(1)) if m else 100.0
    m = RTT_RE.search(output)
    latency = float(m.group(2)) if m else PING_TIMEOUT_MS
    return latency, loss


def fix_owner(path):
    """If run via sudo, give the file back to the real user."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid:
        try:
            os.chown(path, int(uid), int(gid))
        except OSError:
            pass


class MetricsCollector:
    def __init__(self, net, interval=5.0, src=PROBE_SRC, target=TARGET,
                 target_ip=WEB_IP, iface=TARGET_IFACE):
        self.src = net.get(src)
        self.target = net.get(target)
        self.target_ip = target_ip
        self.iface = iface
        self.interval = interval

    def _probe(self):
        out = self.src.cmd(f"ping -c 5 -i 0.2 -W 1 -q {self.target_ip}")
        return parse_ping(out)

    def sample(self, label="normal"):
        """Take one measurement and return it as a dict (one CSV row)."""
        window = max(self.interval - 0.7, 1.0)
        sniffer = self.target.popen(
            [PYTHON, SNIFFER, "--iface", self.iface,
             "--seconds", f"{window:.2f}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True)
        time.sleep(0.2)                       # let the sniffer bind first
        latency, loss = self._probe()
        out, err = sniffer.communicate(timeout=window + 10)
        lines = out.strip().splitlines()
        if not lines:
            raise RuntimeError(f"sniffer produced no output: {err.strip()}")
        s = json.loads(lines[-1])

        dur = max(s["duration"], 0.001)
        return {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "label": label,
            "latency_ms": round(latency, 2),
            "loss_pct": round(loss, 1),
            "throughput_mbps": round(s["bytes"] * 8 / dur / 1e6, 4),
            "pps": round(s["packets"] / dur, 2),
            "syn_ratio": round(s["syn"] / s["tcp"], 4) if s["tcp"] else 0.0,
            "unique_ports_max": s["unique_ports_max"],
            "arp_rate": round(s["arp"] / dur, 3),
            "top_src_ip": s["top_syn_src"],
        }

    def run(self, duration_s, label="normal", csv_path=None):
        """Sample until duration_s has passed, appending rows to a CSV."""
        csv_path = csv_path or os.path.join(DATA_DIR, "baseline.csv")
        os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
        is_new = not os.path.exists(csv_path)
        rows = 0
        with open(csv_path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=COLUMNS)
            if is_new:
                writer.writeheader()
            t_end = time.time() + duration_s
            while time.time() < t_end:
                t0 = time.time()
                row = self.sample(label)
                writer.writerow(row)
                f.flush()
                rows += 1
                print(f"[{rows:4d}] {row['timestamp']}  "
                      f"lat={row['latency_ms']:7.2f}ms  "
                      f"loss={row['loss_pct']:5.1f}%  "
                      f"thr={row['throughput_mbps']:7.3f}Mbps  "
                      f"pps={row['pps']:8.1f}  "
                      f"syn={row['syn_ratio']:.2f}  "
                      f"ports={row['unique_ports_max']}", flush=True)
                time.sleep(max(0.0, self.interval - (time.time() - t0)))
        fix_owner(os.path.dirname(csv_path) or ".")
        fix_owner(csv_path)
        return rows
