#!/usr/bin/env python3
"""Generate a synthetic dataset conforming to Mininet scenarios.
Useful when Mininet cannot be run or to bootstrap models immediately.
"""
import os
import random
import datetime
import numpy as np
import pandas as pd
from config import DATA_DIR, FEATURES

CLASSES = ["normal", "syn_flood", "port_scan", "link_failure", "congestion"]

def generate_samples(label, n=18):
    rows = []
    for _ in range(n):
        if label == "normal":
            r = {
                "latency_ms": round(float(np.random.normal(10.5, 1.0)), 2),
                "loss_pct": 0.0,
                "throughput_mbps": round(float(np.random.uniform(0.02, 0.06)), 4),
                "pps": round(float(np.random.uniform(30.0, 50.0)), 1),
                "syn_ratio": round(float(np.random.uniform(0.08, 0.14)), 3),
                "unique_ports_max": 1,
                "arp_rate": round(float(np.random.uniform(0.0, 0.05)), 2),
                "top_src_ip": ""
            }
        elif label == "syn_flood":
            r = {
                "latency_ms": round(float(np.random.normal(22.0, 4.0)), 2),
                "loss_pct": round(float(np.random.uniform(0.0, 4.0)), 1),
                "throughput_mbps": round(float(np.random.uniform(0.8, 2.2)), 4),
                "pps": round(float(np.random.uniform(700.0, 1800.0)), 1),
                "syn_ratio": round(float(np.random.uniform(0.88, 0.98)), 3),
                "unique_ports_max": 1,
                "arp_rate": round(float(np.random.uniform(0.0, 0.05)), 2),
                "top_src_ip": "10.0.1.14"
            }
        elif label == "port_scan":
            r = {
                "latency_ms": round(float(np.random.normal(12.0, 1.5)), 2),
                "loss_pct": 0.0,
                "throughput_mbps": round(float(np.random.uniform(0.15, 0.45)), 4),
                "pps": round(float(np.random.uniform(300.0, 750.0)), 1),
                "syn_ratio": round(float(np.random.uniform(0.85, 0.95)), 3),
                "unique_ports_max": int(np.random.randint(60, 250)),
                "arp_rate": round(float(np.random.uniform(0.0, 0.05)), 2),
                "top_src_ip": "10.0.1.14"
            }
        elif label == "link_failure":
            r = {
                "latency_ms": 1000.0,
                "loss_pct": 100.0,
                "throughput_mbps": 0.0,
                "pps": 0.0,
                "syn_ratio": 0.0,
                "unique_ports_max": 0,
                "arp_rate": 0.0,
                "top_src_ip": ""
            }
        elif label == "congestion":
            r = {
                "latency_ms": round(float(np.random.normal(125.0, 20.0)), 2),
                "loss_pct": round(float(np.random.uniform(8.0, 22.0)), 1),
                "throughput_mbps": round(float(np.random.uniform(8.2, 9.6)), 4),
                "pps": round(float(np.random.uniform(750.0, 1100.0)), 1),
                "syn_ratio": round(float(np.random.uniform(0.01, 0.04)), 3),
                "unique_ports_max": 1,
                "arp_rate": round(float(np.random.uniform(0.0, 0.05)), 2),
                "top_src_ip": "10.0.1.12"
            }
        r["label"] = label
        rows.append(r)
    return rows

def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    out_file = os.path.join(DATA_DIR, "dataset.csv")
    cur_time = datetime.datetime.now() - datetime.timedelta(hours=2)
    all_rows = []
    
    rounds = 6
    for rnd in range(rounds):
        scenarios_in_round = list(CLASSES)
        random.shuffle(scenarios_in_round)
        for sc in scenarios_in_round:
            # 18 samples per scenario (~90s at 5s intervals)
            samples = generate_samples(sc, n=18)
            for row in samples:
                row["timestamp"] = cur_time.isoformat()
                all_rows.append(row)
                cur_time += datetime.timedelta(seconds=5)
            cur_time += datetime.timedelta(seconds=20) # gap between scenarios
            
    df = pd.DataFrame(all_rows)
    cols = ["timestamp", "label"] + FEATURES + ["top_src_ip"]
    df = df[cols]
    df.to_csv(out_file, index=False)
    print(f"Generated {len(df)} samples into {out_file}")

if __name__ == "__main__":
    main()
