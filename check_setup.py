#!/usr/bin/env python3
"""Checks that this computer is ready to run the project. Changes nothing.

    venv/bin/python check_setup.py
"""
import importlib
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
problems = []


def line(ok, text, fix=""):
    print(("  OK    " if ok else "  FAIL  ") + text)
    if not ok:
        problems.append(fix or text)
        if fix:
            print("        fix: " + fix)


print("Python")
line(sys.version_info >= (3, 10), f"Python {sys.version.split()[0]} (need 3.10 or newer)",
     "install Python 3.10+ (sudo apt install python3 python3-venv python3-pip)")
if sys.prefix == sys.base_prefix:
    print("  note  not inside a virtual environment (fine if the packages below are installed)")

print("Python packages")
for mod, pip in (("numpy", "numpy"), ("pandas", "pandas"), ("sklearn", "scikit-learn"),
                 ("joblib", "joblib"), ("flask", "flask"), ("flask_login", "flask-login"),
                 ("flask_sqlalchemy", "flask-sqlalchemy"), ("cryptography", "cryptography"),
                 ("apscheduler", "apscheduler"), ("reportlab", "reportlab")):
    try:
        importlib.import_module(mod)
        line(True, mod)
    except ImportError:
        line(False, f"{mod} is missing", f"pip install -r requirements.txt   ({pip})")

print("Mininet (needed only by run_monitor.py, which runs with sudo)")
try:
    importlib.import_module("mininet")
    line(True, "mininet is importable from this Python")
except ImportError:
    line(False, "mininet is not importable from this Python",
         "sudo apt install mininet, then recreate the venv with: "
         "python3 -m venv --system-site-packages venv")
for tool in ("mn", "ovs-vsctl", "iptables", "ip", "tc", "iperf3", "hping3", "nmap"):
    line(shutil.which(tool) is not None, tool,
         "sudo apt install mininet openvswitch-switch iptables iproute2 iperf3 hping3 nmap -y")
if shutil.which("ovs-vsctl"):
    ok = subprocess.run(["pgrep", "-x", "ovs-vswitchd"], capture_output=True).returncode == 0
    line(ok, "Open vSwitch is running", "sudo service openvswitch-switch start")

print("Project files")
for rel in ("models/isolation_forest.joblib", "models/random_forest.joblib"):
    line(os.path.exists(os.path.join(HERE, rel)), rel,
         "copy the models/ folder from the original computer, or retrain (see SETUP.md, step 6)")

print()
if problems:
    print(f"{len(problems)} problem(s). Fix them in the order shown, then run this check again.")
    sys.exit(1)
print("Everything needed is in place. Next: the commands under 'Run it' in SETUP.md.")
