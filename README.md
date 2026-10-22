# Autonomous Network Engineer (ANE)

An autonomous, self-healing network management system with Machine Learning anomaly detection, real-time telemetry streaming, autonomous remediation (failover rerouting, gateway firewall blocking), and a full interactive web dashboard.

---

## Quick Start

### Running on Windows (All-in-One Runner)
The Windows runner executes the simulated network topology, real-time ML anomaly detection, autonomous healer, and web dashboard concurrently without requiring Mininet or WSL:

```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch the runner
python run_windows.py
```
- Open **http://127.0.0.1:5000** in your browser.
- Default Login:
  - **Username:** `Yashraj`
  - **Password:** `password123`

### Running on Linux / WSL2 (Full Mininet Simulation)
See [`SETUP.md`](file:///c:/Users/YASHRAJ/Desktop/CN%20MiniProject/SETUP.md) for full Linux environment setup:
```bash
sudo service openvswitch-switch start
sudo venv/bin/python run_monitor.py    # Terminal 1: Mininet network monitor & healer
python web_app.py                      # Terminal 2: Flask web dashboard
```

---

## Overview

## Files
(Week 4 adds `web_app.py`, `webapp/`, `run_monitor.py`, `control.py`, `reporting.py`, `test_webapp.py`.)
| File | Purpose |
|---|---|
| `config.py` | Addresses, host names, feature list (no Mininet import) |
| `topology.py` | Mininet network: 2 LANs, 3 routers, primary + backup path |
| `traffic.py` | Web server on `web`, HTTP clients on h1,h2,h3,h5,h6 |
| `sniff_window.py` | Counts inbound packets at the web server for one window |
| `collector.py` | Builds one feature row per ~5 s and appends it to a CSV |
| `run_baseline.py` | Starts everything and records the CSV |

## Network
```
 h1 h2 h3 h4(attacker)                     h5 h6 web(10.0.2.100)
     \ | | /                                   \ | /
       s1 --- r1 ======= primary ======= r2 --- s2
                 \                      /
                  +------- r3 ---------+   (backup path)
```
Only the primary routes are installed at start. The backup path is used when
you (or, from Week 3, the healer) reroute.

## Run
```bash
cd ~/autonomous-network-engineer
source venv/bin/activate          # once per terminal (optional, see below)
sudo service openvswitch-switch start

# quick 1-minute test
sudo venv/bin/python run_baseline.py --minutes 1 --out data/test.csv

# real baseline: 20 minutes of normal traffic
sudo venv/bin/python run_baseline.py --minutes 20 --out data/baseline.csv
```
Use `sudo venv/bin/python` (not plain `sudo python`) so sudo uses the venv.

If a run was killed and Mininet complains, clean up with `sudo mn -c`.

## Explore by hand
```bash
sudo venv/bin/python run_baseline.py --cli
```
In the `ane>` prompt:
```
h1 ping -c 3 web          # works over the primary path
primary_down              # simulate link failure
h1 ping -c 3 web          # 100% loss
use_backup                # reroute via r3
h1 ping -c 3 web          # works again, higher latency
primary_up                # restore
```

## CSV columns
`timestamp, label, latency_ms, loss_pct, throughput_mbps, pps, syn_ratio,
unique_ports_max, arp_rate, top_src_ip`

* Traffic features are measured on the web server's inbound traffic.
* `latency_ms` is 1000 and `loss_pct` is 100 when every probe ping is lost.
* `top_src_ip` is metadata for the healer, not a model feature.

## Week 2: labeled dataset
| File | Purpose |
|---|---|
| `scenarios.py` | normal, syn_flood (hping3), port_scan (nmap), link_failure, congestion (iperf3) |
| `generate_dataset.py` | Cycles through the scenarios and labels every sample |
| `summarize.py` | Row counts and average features per label |

```bash
# smoke test, about 3 minutes
sudo venv/bin/python generate_dataset.py --rounds 1 --seconds 30 --out data/smoke.csv
python summarize.py data/smoke.csv

# full dataset, about 50 minutes
sudo venv/bin/python generate_dataset.py --rounds 6 --seconds 90
python summarize.py data/dataset.csv
```
Only one Mininet script can run at a time, so wait for one to finish before
starting another. port_scan samples are automatically capped at 75 s per
round, because a full nmap scan ends after about 80 s.

## Week 2: training the models
```bash
pip install matplotlib            # optional, only for the confusion-matrix image
python train_models.py
```
Reads `data/dataset.csv` (and `data/baseline.csv` as extra normal data) and
prints:
* Stage 1, Isolation Forest vs a simple threshold rule (loss > 10% or
  latency > 100 ms): false-alarm rate on normal traffic and detection rate
  per attack type
* Stage 2, Random Forest: accuracy, precision/recall/F1 per class, confusion
  matrix, feature importance, leave-one-round-out cross-validation
* Both stages together, as the decision engine will use them

Whole rounds are held out for testing (default the last 2 of 6) so that
near-identical samples from one scenario run never sit on both sides of the
split. Final models are refit on all data and saved to `models/`
(`isolation_forest.joblib`, `random_forest.joblib`, `metrics.json`,
`confusion_matrix.png`). `--fpr 0.02` sets the Isolation Forest's target
false-alarm rate on training data; raise it to catch more, lower it for fewer
false alarms.

## Week 3: detect, decide, heal, verify
| File | Purpose |
|---|---|
| `detector.py` | Loads `models/` and labels one sample: normal, syn_flood, port_scan, link_failure, congestion or unknown |
| `decision.py` | Decision engine: confirms a problem, picks an action, applies the mode, verifies, rolls back |
| `healing.py` | The actions (`BlockSource`, `Reroute`), the dry-run executor, block expiry and fail-back |
| `audit.py` | Writes every step to `data/audit.jsonl` |
| `test_healing.py` | 27 logic tests, no Mininet or sudo needed: `python test_healing.py` |
| `run_demo.py` | Injects a fault on the simulated network and runs the whole loop, with before/after metrics and MTTD/MTTR |

```bash
sudo service openvswitch-switch start
sudo venv/bin/python run_demo.py --check                      # environment check
sudo venv/bin/python run_demo.py --scenario link_failure
sudo venv/bin/python run_demo.py --scenario syn_flood
sudo venv/bin/python run_demo.py --scenario port_scan
sudo venv/bin/python run_demo.py --scenario latency_spike
sudo venv/bin/python run_demo.py --scenario all --repeat 3    # MTTD/MTTR over 15 runs
sudo venv/bin/python run_demo.py --scenario normal --minutes 10   # false-alarm check
```
Options: `--mode monitor|approval|auto` (default auto), `--dry-run` (print the
commands, change nothing), `--confirm N` (samples in a row before acting,
default 2), `--block-ttl SECONDS` (default 600, 0 = never expire).

### What the engine does
| Problem | Action | Verified by |
|---|---|---|
| syn_flood | block the top SYN source at its gateway router | models see normal traffic again |
| port_scan | block (quarantine) the scanning source | models see normal traffic again |
| link_failure | reroute r1 and r2 traffic via r3 | probe loss <= 10% and latency <= 100 ms |
| congestion | reroute only if the link is not full; if a heavy flow fills it, advise only | as for reroute |
| degraded_link | the Isolation Forest says abnormal, the Random Forest cannot name it, and loss > 10% or latency > 100 ms: reroute unless the link is full | as for reroute |
| unknown | abnormal but the service still looks healthy: log only | |

Safety: monitor / approval / auto modes, dry run, a problem must be seen in
`--confirm` consecutive samples, the server, routers and probe host can never
be blocked, blocks expire by themselves, failed fixes are rolled back and are
not retried until the problem has been gone for 3 samples, and every step is
written to `data/audit.jsonl`. Traffic returns to the primary path on its own
once r1-r2 answers pings at a normal latency (first check 15 s after a
reroute, so traffic cannot flip straight back).

A slow link (latency spike) is not one of the five trained classes, so the
Random Forest cannot name it. The engine does not trust an `unknown` label
on its own, but when the service is hurting (loss or latency past the health
limits in `config.py`) it treats the sample as `degraded_link` and reroutes,
with the same verification and rollback. `run_demo.py` prints the labels the
models gave during each fault, so you can see exactly what they saw.

Reroute is verified by probe loss and latency, not by the Isolation Forest,
because the backup path is legitimately slower and the model may still call it
unusual.

Limits: a source on the same LAN as the server cannot be blocked at a router
(the engine reports this instead of acting), and the models were trained on
strong attacks, so slow scans or low-rate floods may not be detected.

## Week 4: web app (login, networks, dashboard, reports)

Install once (inside the venv):
```bash
pip install flask flask-login flask-sqlalchemy cryptography apscheduler reportlab
```
Run two programs in two Ubuntu windows, from the project folder:
```bash
# window 1: the monitor (needs sudo; starts the simulated network and heals it)
sudo service openvswitch-switch start
sudo venv/bin/python run_monitor.py            # options: --mode approval, --dry-run
# window 2: the web app (no sudo)
venv/bin/python web_app.py --report-every-min 60
```
Open http://127.0.0.1:5000 in your Windows browser.

1. First visit: create the one administrator account (8+ characters). Setup closes
   itself once the account exists.
2. Networks: add a name, a subnet, optional device list and the device
   username/password. The password is encrypted with Fernet before it is saved
   (key in `data/secret.key`, mode 600) and is never shown again. In the
   simulation, "discovery" matches your devices (or the whole subnet) against
   what Mininet really contains. Try subnet `10.0.1.0/24`, and `10.0.2.0/24`.
3. Dashboard: heartbeat strip (one tick per sample), live numbers, latency and
   packet charts, incident table with detect and recover times, action log, and
   the three modes (Watch only, Ask me first, Fix automatically). In "Ask me
   first" an approval box appears with Apply the fix / Decline (30 s, then it
   counts as declined). The "Try a fault" buttons start a real fault in the
   simulated network, so you can demo from the browser.
4. Reports: pick the period (since the monitor started, last 15 min, hour, 24 h, all), then create; or every N minutes (`--report-every-min`) or with "Create a
   report now"; HTML to view, PDF to download, in `data/reports/`.

How the two programs talk: files in `data/` (`status.json`, `metrics.jsonl`,
`control.json`, `approval.json`). The web app never needs root or Mininet.

Security: passwords hashed (scrypt), CSRF token on every POST, 5 failed logins
lock that address for 60 s, session cookie HttpOnly + SameSite, strict
Content-Security-Policy (no inline scripts), reports served only by a fixed
filename pattern, server listens on 127.0.0.1 only. Do not expose it to a
network without HTTPS in front of it.

Tests: `python test_webapp.py` (41 tests), `python test_healing.py` (31 tests).
Limits: single administrator by design; deleting `data/secret.key` makes stored
credentials unreadable (add the network again); the monitor is bound to the
simulated network, so the registered network is metadata plus device matching.

### Live network view (proof that the fix really happens)

The dashboard shows the simulated network as a picture that is drawn from the
real routers, not from the program's own notes. After every sample, and right
after every change, `netstate.py` reads each router:

| What is read | Command run on the router | What it proves |
|---|---|---|
| Route to the other LAN | `ip route show 10.0.2.0/24` | traffic uses the primary path or the backup via r3 |
| Firewall DROP rules and packet counts | `iptables -v -S FORWARD` | the attacker is blocked and its packets are being dropped |
| Link state and delay | `ip -br link show`, `tc qdisc show` | the primary link is down or slow |

The same page lists every command the healer ran (`/api/commands`) and a
step-by-step timeline of the incident (`/api/timeline`): fault starts, models
flag it, confirmed, fix chosen, applied, verified. To show it to someone, start
`run_monitor.py` and the web app, open the dashboard and press a fault button.
In dry-run mode the picture correctly shows that nothing changed.
