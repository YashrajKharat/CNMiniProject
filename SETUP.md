# Running the project on another computer

The project needs **Linux** (Mininet only works there). On Windows use WSL2 with
Ubuntu 22.04 (or 24.04), or an Ubuntu virtual machine. About 2 GB of disk space.

All commands below are typed in the Ubuntu terminal.

## 1. Install the system tools (once)

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch iptables iproute2 iperf3 hping3 nmap \
                    python3 python3-venv python3-pip unzip
sudo service openvswitch-switch start
```

## 2. Unzip the project

```bash
cd ~
unzip ane_share.zip           # adjust the path, e.g. /mnt/c/Users/<you>/Downloads/ane_share.zip
cd ~/autonomous-network-engineer
```

Unzip inside the Linux home folder (`~`), not on `C:` or `V:`, so file permissions work.

## 3. Create the Python environment (once)

```bash
python3 -m venv --system-site-packages venv
source venv/bin/activate
pip install -r requirements.txt
```

`--system-site-packages` matters: Mininet was installed by apt, and this lets the
venv see it.

## 4. Check everything is ready

```bash
python check_setup.py
```

Fix anything marked FAIL (each line says how), then run it again until it ends with
"Everything needed is in place".

## 5. Run it (two terminals, both in `~/autonomous-network-engineer`)

Terminal 1, the monitor (needs sudo, starts the simulated network):
```bash
sudo service openvswitch-switch start
sudo venv/bin/python run_monitor.py
```
Terminal 2, the web app (no sudo):
```bash
source venv/bin/activate
python web_app.py
```
Open http://127.0.0.1:5000 in the browser. The first visit asks you to create the
administrator account. Then add a network: any name, subnet `10.0.0.0/16`, leave
devices empty (it discovers them), and any device username and password.

On the dashboard press a fault button (Link failure, SYN flood, ...) and watch the
network picture, the router state and the commands. Press **End fault** before
starting another. Stop the monitor with Ctrl+C; it undoes its changes.

If a run was killed and Mininet complains: `sudo mn -c`.

## 6. If the models folder is missing (optional)

The zip normally includes `models/`. If it does not, retrain them from the
included data. It takes about a minute and needs no sudo:
```bash
python train_models.py
```
(Only if `data/dataset.csv` is also missing do you need to generate new labelled
traffic, about 50 minutes: `sudo venv/bin/python generate_dataset.py --rounds 6 --seconds 90`.
See README.md, "Week 2".)

## 7. Run the tests (no sudo, no Mininet needed)

```bash
python test_healing.py
python test_webapp.py
```
Both should end with OK.

## Common problems

| Message | Fix |
|---|---|
| `venv/bin/python: No such file or directory` | You are not in the project folder. `cd ~/autonomous-network-engineer` |
| `ModuleNotFoundError: mininet` | Recreate the venv with `--system-site-packages` (step 3) |
| `Run with sudo` | Start the monitor with `sudo venv/bin/python run_monitor.py` |
| Dashboard says the monitor is not running | Start terminal 1 first and wait about 20 s |
| Mininet errors about existing interfaces | `sudo mn -c`, then start again |
| Port 5000 busy | `python web_app.py --port 5001` |
| scikit-learn version warning when loading models | Harmless. To remove it, retrain (step 6) |
