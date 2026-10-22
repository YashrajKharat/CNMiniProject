#!/usr/bin/env python3
"""Autonomous Network Engineer - Native Windows All-In-One Runner.

Runs the complete project natively on Windows without requiring Linux, WSL, or sudo:
  - Simulated Network Routers & Virtual Links
  - Real Machine Learning Anomaly Detection (Isolation Forest & Random Forest)
  - Real Autonomous Self-Healing Decision Engine (Firewall Blocking & Backup Rerouting)
  - Live Flask Web Management Dashboard on http://127.0.0.1:5000

Usage:
    python run_windows.py
    python run_windows.py --mode approval
    python run_windows.py --port 5000
"""
import argparse
import os
import re
import sys
import time
import random
import threading
import webbrowser
from datetime import datetime
import numpy as np

# Ensure this folder is on Python path
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)
try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass


from audit import AuditLog
from config import AUDIT_LOG, DATA_DIR, BACKUP_ROUTES, PRIMARY_ROUTES, PRIMARY_PROBE
import control
from control import MODES, MonitorChannel
from decision import DecisionEngine, say
from detector import Detector
from healing import Healer, BlockSource
import netstate
from webapp import create_app

FAULT_MAX_S = 120
AFTER_FIX_S = 15

class WindowsRouterSimulator:
    """Simulates real Linux router command execution (routes, iptables, links, tc)."""
    dry_run = False

    def __init__(self, on_run=None):
        self.on_run = on_run
        self.rules = set()  # set of (router, ip)
        self.packet_counts = {}
        self.routes = {
            ("r1", "10.0.2.0/24"): "via 10.0.12.2",
            ("r2", "10.0.1.0/24"): "via 10.0.12.1",
        }
        self.primary_link_up = True
        self.primary_delay_ms = None

    def run(self, node, cmd):
        rc, out = 0, ""
        
        # compound commands or shell loops
        if cmd.startswith("while iptables") or "; do iptables" in cmd:
            m = re.search(r"-s ([\d\.]+)", cmd)
            if m:
                ip = m.group(1)
                self.rules.discard((node, ip))
            rc, out = 0, ""
        elif cmd.startswith("while ip rule del") or "; do :; done" in cmd:
            m = re.search(r"from ([\d\.]+)", cmd)
            if m:
                ip = m.group(1)
                self.rules.discard((node, ip))
            rc, out = 0, ""
        
        # iptables checks and rules
        elif cmd.startswith("iptables -S"):
            rc, out = 0, "-P FORWARD ACCEPT"
        elif "iptables -v -S FORWARD" in cmd:
            lines = ["-P FORWARD ACCEPT"]
            for r, ip in sorted(self.rules):
                if r == node:
                    pkts = self.packet_counts.get((r, ip), random.randint(120, 850))
                    lines.append(f"-A FORWARD -s {ip}/32 -c {pkts} {pkts*64} -j DROP")
            rc, out = 0, "\n".join(lines)
        elif "iptables -I FORWARD" in cmd:
            m = re.search(r"-s ([\d\.]+)", cmd)
            if m:
                ip = m.group(1)
                self.rules.add((node, ip))
                self.packet_counts[(node, ip)] = 124
            rc, out = 0, ""
        elif "iptables -D FORWARD" in cmd:
            m = re.search(r"-s ([\d\.]+)", cmd)
            if m:
                ip = m.group(1)
                self.rules.discard((node, ip))
            rc, out = 0, ""
        elif "iptables -C FORWARD" in cmd:
            if "||" in cmd:
                # Compound command: iptables -C ... || iptables -I ...
                # Rule check failed -> executes || branch -> rule gets added
                m = re.search(r"-s ([\d\.]+)", cmd)
                ip = m.group(1) if m else ""
                if (node, ip) not in self.rules:
                    self.rules.add((node, ip))
                    self.packet_counts[(node, ip)] = 124
                rc, out = 0, ""
            else:
                # Direct check
                m = re.search(r"-s ([\d\.]+)", cmd)
                ip = m.group(1) if m else ""
                if (node, ip) in self.rules:
                    rc, out = 0, ""
                else:
                    rc, out = 1, "rule does not exist"

        # ip rule commands
        elif "ip rule add" in cmd:
            m = re.search(r"from ([\d\.]+)", cmd)
            if m:
                ip = m.group(1)
                self.rules.add((node, ip))
            rc, out = 0, ""
        elif "ip rule show" in cmd and "grep" in cmd:
            m = re.search(r"from ([\d\.]+)", cmd)
            ip = m.group(1) if m else ""
            if (node, ip) in self.rules:
                rc, out = 0, ""
            else:
                rc, out = 1, "no matching ip rule"

        # ip route commands
        elif cmd.startswith("ip route show"):
            prefix = cmd.split()[-1]
            via = self.routes.get((node, prefix), "via 10.0.12.2")
            rc, out = 0, f"{prefix} {via} dev eth1"
        elif "ip route replace" in cmd:
            parts = cmd.split()
            prefix = parts[parts.index("replace") + 1]
            via = parts[parts.index("via") + 1]
            self.routes[(node, prefix)] = f"via {via}"
            rc, out = 0, ""
        elif "ip route del" in cmd:
            prefix = cmd.split()[-1]
            self.routes.pop((node, prefix), None)
            rc, out = 0, ""

        # link and tc qdisc commands
        elif "ip -br link show" in cmd:
            status = "UP" if self.primary_link_up else "DOWN"
            rc, out = 0, f"r1-eth1 {status} 10.0.12.1/30"
        elif "tc qdisc show" in cmd:
            if self.primary_delay_ms:
                rc, out = 0, f"qdisc netem 1: dev r1-eth1 delay {self.primary_delay_ms}ms"
            else:
                rc, out = 0, "qdisc fq_codel 0: dev r1-eth1 root"

        # ping commands
        elif "ping -c" in cmd:
            if self.primary_link_up:
                delay = self.primary_delay_ms or 10.5
                rc, out = 0, f"2 packets transmitted, 2 received, 0% packet loss\nmin/avg/max = 9.8/{delay:.1f}/11.2 ms"
            else:
                rc, out = 1, "2 packets transmitted, 0 received, 100% packet loss"
        else:
            rc, out = 0, ""

        if self.on_run:
            self.on_run(node, cmd, rc, out)
        return rc, out


def _normal_telemetry():
    return {
        "latency_ms": round(float(np.clip(np.random.normal(10.38, 0.45), 9.2, 11.5)), 2),
        "loss_pct": 0.0,
        "throughput_mbps": round(float(np.random.uniform(0.032, 0.048)), 4),
        "pps": round(float(np.random.uniform(36.0, 45.0)), 1),
        "syn_ratio": round(float(np.random.uniform(0.095, 0.128)), 3),
        "unique_ports_max": 1,
        "arp_rate": round(float(np.random.uniform(0.015, 0.035)), 2),
        "top_src_ip": ""
    }


def generate_simulated_sample(fault, router_sim):
    """Generates real-time telemetry matching live Mininet traffic scenarios."""
    is_blocked = ("r1", "10.0.1.14") in router_sim.rules
    on_backup = "10.0.13.2" in router_sim.routes.get(("r1", "10.0.2.0/24"), "")

    if fault == "link_failure":
        if on_backup:
            # Rerouted through r3 successfully
            return {
                "latency_ms": round(float(np.random.normal(16.5, 1.2)), 2),
                "loss_pct": 0.0,
                "throughput_mbps": round(float(np.random.uniform(0.03, 0.06)), 4),
                "pps": round(float(np.random.uniform(35.0, 48.0)), 1),
                "syn_ratio": round(float(np.random.uniform(0.08, 0.13)), 3),
                "unique_ports_max": 1,
                "arp_rate": 0.0,
                "top_src_ip": ""
            }
        else:
            # Primary link is down and un-rerouted
            return {
                "latency_ms": 1000.0,
                "loss_pct": 100.0,
                "throughput_mbps": 0.0,
                "pps": 0.0,
                "syn_ratio": 0.0,
                "unique_ports_max": 0,
                "arp_rate": 0.0,
                "top_src_ip": ""
            }

    elif fault == "syn_flood":
        if is_blocked:
            # Attacker dropped at r1 gateway
            return _normal_telemetry()
        else:
            # Attack in progress
            return {
                "latency_ms": round(float(np.random.normal(24.0, 3.5)), 2),
                "loss_pct": round(float(np.random.uniform(0.0, 3.0)), 1),
                "throughput_mbps": round(float(np.random.uniform(1.2, 2.4)), 4),
                "pps": round(float(np.random.uniform(900.0, 1600.0)), 1),
                "syn_ratio": round(float(np.random.uniform(0.92, 0.98)), 3),
                "unique_ports_max": 1,
                "arp_rate": 0.0,
                "top_src_ip": "10.0.1.14"
            }

    elif fault == "port_scan":
        if is_blocked:
            return _normal_telemetry()
        else:
            return {
                "latency_ms": round(float(np.random.normal(12.0, 1.2)), 2),
                "loss_pct": 0.0,
                "throughput_mbps": round(float(np.random.uniform(0.20, 0.45)), 4),
                "pps": round(float(np.random.uniform(400.0, 750.0)), 1),
                "syn_ratio": round(float(np.random.uniform(0.86, 0.94)), 3),
                "unique_ports_max": int(np.random.randint(80, 220)),
                "arp_rate": 0.0,
                "top_src_ip": "10.0.1.14"
            }

    elif fault == "congestion":
        if on_backup:
            return {
                "latency_ms": round(float(np.random.normal(18.0, 2.0)), 2),
                "loss_pct": 0.0,
                "throughput_mbps": round(float(np.random.uniform(0.04, 0.08)), 4),
                "pps": round(float(np.random.uniform(40.0, 60.0)), 1),
                "syn_ratio": round(float(np.random.uniform(0.08, 0.12)), 3),
                "unique_ports_max": 1,
                "arp_rate": 0.0,
                "top_src_ip": ""
            }
        else:
            return {
                "latency_ms": round(float(np.random.normal(135.0, 22.0)), 2),
                "loss_pct": round(float(np.random.uniform(10.0, 25.0)), 1),
                "throughput_mbps": round(float(np.random.uniform(8.5, 9.6)), 4),
                "pps": round(float(np.random.uniform(800.0, 1150.0)), 1),
                "syn_ratio": round(float(np.random.uniform(0.01, 0.03)), 3),
                "unique_ports_max": 1,
                "arp_rate": 0.0,
                "top_src_ip": "10.0.1.12"
            }

    elif fault == "latency_spike":
        if on_backup:
            return {
                "latency_ms": round(float(np.random.normal(18.0, 1.5)), 2),
                "loss_pct": 0.0,
                "throughput_mbps": round(float(np.random.uniform(0.03, 0.05)), 4),
                "pps": round(float(np.random.uniform(32.0, 48.0)), 1),
                "syn_ratio": round(float(np.random.uniform(0.08, 0.12)), 3),
                "unique_ports_max": 1,
                "arp_rate": 0.0,
                "top_src_ip": ""
            }
        else:
            return {
                "latency_ms": round(float(np.random.normal(160.0, 15.0)), 2),
                "loss_pct": 0.0,
                "throughput_mbps": round(float(np.random.uniform(0.03, 0.05)), 4),
                "pps": round(float(np.random.uniform(32.0, 48.0)), 1),
                "syn_ratio": round(float(np.random.uniform(0.08, 0.12)), 3),
                "unique_ports_max": 1,
                "arp_rate": 0.0,
                "top_src_ip": ""
            }

    # Normal healthy traffic
    return _normal_telemetry()


def sync_app_data(data_dir):
    """Ensure database, user credentials, and active network configuration
    are always synchronized between root and autonomous-network-engineer/ subfolders,
    and seed a persistent administrator account so setup is never required repeatedly."""
    import shutil
    import sqlite3

    candidates = [
        os.path.abspath(os.path.join(PROJECT_DIR, "data")),
        os.path.abspath(os.path.join(PROJECT_DIR, "autonomous-network-engineer", "data")),
        os.path.abspath(os.path.join(PROJECT_DIR, "..", "data")),
    ]
    current_db = os.path.abspath(os.path.join(data_dir, "app.db"))
    
    def count_users(db_path):
        if not os.path.isfile(db_path):
            return 0
        try:
            con = sqlite3.connect(db_path)
            res = con.execute("SELECT count(*) FROM user").fetchone()[0]
            con.close()
            return res
        except Exception:
            return 0

    curr_count = count_users(current_db)
    if curr_count == 0:
        for c in candidates:
            cand_db = os.path.abspath(os.path.join(c, "app.db"))
            if cand_db != current_db and count_users(cand_db) > 0:
                print(f"[+] Restored persistent user account from: {cand_db}")
                shutil.copy2(cand_db, current_db)
                for key_file in ("flask_secret", "secret.key", "settings.json"):
                    src = os.path.join(c, key_file)
                    dst = os.path.join(data_dir, key_file)
                    if os.path.isfile(src):
                        shutil.copy2(src, dst)
                curr_count = count_users(current_db)
                break

    if curr_count == 0:
        from webapp import create_app as _tmp_app, db as _db, User as _User, Network as _Net
        from werkzeug.security import generate_password_hash
        t_app = _tmp_app(data_dir)
        with t_app.app_context():
            if _User.query.first() is None:
                u = _User(username="Yashraj", password_hash=generate_password_hash("password123"))
                _db.session.add(u)
                net = _Net(name="L10", subnet="10.0.1.0/24", devices="[]",
                           cred_enc=t_app.vault.seal({"username": "admin", "password": "password"}),
                           active=True)
                _db.session.add(net)
                try:
                    _db.session.commit()
                except Exception:
                    _db.session.rollback()
            print("[+] Initialized persistent administrator account: Yashraj")

    # Mirror active app.db and keys to other candidate data directories
    for c in candidates:
        cand_db = os.path.abspath(os.path.join(c, "app.db"))
        if cand_db != current_db and os.path.isdir(c):
            try:
                shutil.copy2(current_db, cand_db)
                for key_file in ("flask_secret", "secret.key", "settings.json"):
                    src = os.path.join(data_dir, key_file)
                    dst = os.path.join(c, key_file)
                    if os.path.isfile(src):
                        shutil.copy2(src, dst)
            except Exception:
                pass


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--mode", choices=MODES, default="auto", help="decision mode (auto, approval, monitor)")
    ap.add_argument("--port", type=int, default=5000, help="web dashboard port")
    ap.add_argument("--interval", type=float, default=5.0, help="telemetry sample interval in seconds")
    ap.add_argument("--confirm", type=int, default=2, help="samples before acting")
    ap.add_argument("--block-ttl", type=int, default=600, help="seconds before firewall block auto-expires")
    args = ap.parse_args()

    os.makedirs(DATA_DIR, exist_ok=True)
    sync_app_data(DATA_DIR)

    print("\n" + "=" * 65)
    print("  AUTONOMOUS NETWORK ENGINEER (ANE) - WINDOWS ALL-IN-ONE RUNNER")
    print("=" * 65)

    # 1. Initialize Machine Learning Detector
    try:
        detector = Detector()
        print("[+] Loaded trained models: Isolation Forest & Random Forest")
    except Exception as e:
        print(f"[-] Model loading failed: {e}")
        print("[+] Training models now...")
        import generate_synthetic_dataset
        generate_synthetic_dataset.main()
        import train_models
        train_models.main()
        detector = Detector()

    # 2. Setup Simulated Router Executor & Healing Engine
    audit = AuditLog(AUDIT_LOG)
    chan = MonitorChannel(DATA_DIR, dry_run=False)
    
    def log_cmd(node, cmd, rc, out):
        chan.log_command(node, cmd, rc, out, False)
        if chan.last_was_change:
            chan.refresh_net(read_net(), live["fault"])

    router_sim = WindowsRouterSimulator(on_run=log_cmd)
    read_net = lambda: netstate.snapshot(router_sim.run)
    healer = Healer(router_sim, audit, block_ttl=args.block_ttl)
    live = {"fault": None}

    def sample_fn():
        row = generate_simulated_sample(live["fault"], router_sim)
        det = detector.classify(row)
        chan.publish(row, det, engine.mode, healer, fault=live["fault"], net_state=read_net())
        return row, det

    engine = DecisionEngine(healer, audit, sample_fn, mode=args.mode,
                            confirm_n=args.confirm, approver=chan.approver(lambda: healer))
    audit.write("session_start", mode=args.mode, dry_run=False, scenario="windows live monitor")

    # 3. Start Flask Web Server in a Background Daemon Thread
    flask_app = create_app(DATA_DIR)
    
    def run_flask():
        flask_app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False, threaded=True)

    web_thread = threading.Thread(target=run_flask, daemon=True)
    web_thread.start()

    url = f"http://127.0.0.1:{args.port}"
    with flask_app.app_context():
        from webapp import User, Network
        active_u = User.query.first()
        active_net = Network.query.filter_by(active=True).first()
        user_name = active_u.username if active_u else "Yashraj"
        net_name = f"{active_net.name} ({active_net.subnet})" if active_net else "L10 (10.0.1.0/24)"

    print(f"\n[+] Web Application listening on: {url}")
    print(f"    - Dashboard: {url}/dashboard")
    print(f"    - Operator Profile: {user_name}")
    print(f"    - Monitored Network: {net_name}")
    print(f"    - Operating Mode: {args.mode.upper()}")
    print("\n[+] Opening dashboard in default browser...")
    try:
        webbrowser.open(f"{url}/dashboard")
    except Exception:
        pass

    print("\n[+] Autonomous Network Monitor is actively running!")
    print("    Press Ctrl+C to stop.\n" + "-" * 65)

    fault, fault_t0, closed_at = None, 0.0, None

    try:
        while True:
            engine.mode = chan.mode(engine.mode)

            # Check if user clicked a fault button on the Web Dashboard
            if fault is None:
                requested_fault = chan.take_injection()
                if requested_fault:
                    fault = requested_fault
                    fault_t0 = time.time()
                    closed_at = None
                    chan.fault_since = fault_t0
                    live["fault"] = fault
                    
                    # Update router simulator states for fault
                    if fault == "link_failure":
                        router_sim.primary_link_up = False
                    elif fault == "latency_spike":
                        router_sim.primary_delay_ms = 150.0

                    chan.refresh_net(read_net(), fault)
                    engine.reset()
                    audit.write("fault_injected", scenario=fault, epoch=round(fault_t0, 3), source="dashboard")
                    say(f">>> [FAULT INJECTED FROM DASHBOARD]: {fault}")

            # Process manual quarantine or release requests from dashboard
            ctrl = control.read_json(chan.p["control"], {}) or {}
            need_net_refresh = False
            if ctrl.get("manual_unblocks"):
                for u_ip in list(ctrl["manual_unblocks"]):
                    if u_ip in healer.blocks:
                        act, _ = healer.blocks[u_ip]
                        healer.rollback(act, incident_id=0, why="operator manual release")
                    else:
                        router_sim.run("r1", f"while iptables -C FORWARD -s {u_ip} -j DROP; do iptables -D FORWARD -s {u_ip} -j DROP; done")
                        audit.write("block_released", action="block_source", what=f"manual release {u_ip}", ok=True)
                ctrl["manual_unblocks"] = []
                control.write_json(chan.p["control"], ctrl)
                need_net_refresh = True

            if ctrl.get("manual_blocks"):
                for b_ip in list(ctrl["manual_blocks"]):
                    act = BlockSource(b_ip, "operator manual quarantine")
                    healer.apply(act, incident_id=0)
                ctrl["manual_blocks"] = []
                control.write_json(chan.p["control"], ctrl)
                need_net_refresh = True

            if need_net_refresh:
                chan.refresh_net(read_net(), live["fault"])

            # Sample metrics and process with AI detection + healing
            sample, det = sample_fn()
            
            # Print periodic heartbeats to console
            ts = datetime.now().strftime("%H:%M:%S")
            state_str = f"[{ts}] Path: {read_net().get('path', 'primary')} | Loss: {sample['loss_pct']:.0f}% | Lat: {sample['latency_ms']:.1f}ms | Label: {det.label.upper()}"
            if det.abnormal:
                state_str += " [ANOMALY DETECTED]"
            print(state_str)

            incident = engine.process(sample, det)
            healer.tick()

            # Handle fault duration and recovery
            if fault is not None:
                if incident is not None and closed_at is None:
                    closed_at = time.time()
                
                stop = (chan.wants_stop_fault()
                        or time.time() - fault_t0 > FAULT_MAX_S
                        or (closed_at is not None and time.time() - closed_at > AFTER_FIX_S))
                
                if stop:
                    say(f">>> [FAULT RESOLVED / REMOVED]: {fault}")
                    router_sim.primary_link_up = True
                    router_sim.primary_delay_ms = None
                    healer.cleanup()
                    chan.clear_stop_fault()
                    audit.write("fault_removed", scenario=fault)
                    fault, closed_at = None, None
                    live["fault"] = None
                    chan.refresh_net(read_net(), None)
                    engine.reset()

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n\n[!] Stopping Autonomous Network Engineer...")
    finally:
        healer.cleanup()
        chan.offline()
        print("[+] Cleanup complete. Shutdown successfully.")


if __name__ == "__main__":
    main()
