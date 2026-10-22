"""Attack and fault scenarios, each a context manager.

    with scenarios.syn_flood(net):
        ...          # attack is running here
                     # attack is stopped and the network restored here

All attacks run between hosts of the simulated network only (h4 -> web).
Every scenario varies its intensity a little so the labeled dataset is not
perfectly uniform.
"""
import random
import subprocess
from contextlib import contextmanager

import topology as T
import traffic
from config import ATTACKER, WEB_IP

DEVNULL = subprocess.DEVNULL


@contextmanager
def normal(net):
    """No fault: label 'normal' while clients keep browsing."""
    yield


@contextmanager
def syn_flood(net):
    """h4 sends 500-2000 SYNs/s to web:80 from one fixed source address."""
    rate = random.choice([500, 1000, 1500, 2000])
    interval = int(1_000_000 / rate)                  # microseconds
    proc = net.get(ATTACKER).popen(
        ["hping3", "-S", "-p", "80", "-i", f"u{interval}", WEB_IP],
        stdout=DEVNULL, stderr=DEVNULL)
    try:
        yield
    finally:
        traffic.stop_processes([proc])


@contextmanager
def port_scan(net):
    """h4 SYN-scans all 65535 ports of web at 200-800 packets/s.
    A full scan takes over 80 s; generate_dataset.py caps this scenario at 75 s."""
    rate = random.choice([200, 400, 600, 800])
    proc = net.get(ATTACKER).popen(
        ["nmap", "-sS", "-n", "-Pn", "-T4", "--max-rate", str(rate),
         "-p-", WEB_IP],
        stdout=DEVNULL, stderr=DEVNULL)
    try:
        yield
    finally:
        traffic.stop_processes([proc])


@contextmanager
def link_failure(net):
    """The primary r1-r2 link goes down; nothing reroutes automatically."""
    T.primary_link_down(net)
    try:
        yield
    finally:
        T.primary_link_up(net)
        T.use_primary(net)


@contextmanager
def congestion(net):
    """h2 pushes iperf3 traffic at web and fills the 10 Mbit primary link."""
    streams = random.choice([1, 2, 4])
    server = net.get("web").popen(["iperf3", "-s"],
                                  stdout=DEVNULL, stderr=DEVNULL)
    client = None
    try:
        import time
        time.sleep(1)                                 # let the server bind
        client = net.get("h2").popen(
            ["iperf3", "-c", WEB_IP, "-t", "600", "-P", str(streams)],
            stdout=DEVNULL, stderr=DEVNULL)
        yield
    finally:
        traffic.stop_processes([p for p in (client, server) if p])


SCENARIOS = {
    "normal": normal,
    "syn_flood": syn_flood,
    "port_scan": port_scan,
    "link_failure": link_failure,
    "congestion": congestion,
}


# ---------------------------------------------------------- demo-only fault
@contextmanager
def latency_spike(net):
    """Demo 4: the primary link gets slow but stays up (a degraded path).

    Adds 100-200 ms of delay in each direction with netem. If the kernel has
    no netem the link is squeezed to 300 kbit/s instead, so queues build up
    and latency spikes the same way.

    This is deliberately NOT in SCENARIOS: that dict defines the trained
    labels, and generate_dataset.py would turn this into an unknown label.
    """
    delay = random.choice([100, 150, 200])
    undo = []
    for node, intf in (("r1", "r1-eth1"), ("r2", "r2-eth1")):
        host = net.get(node)
        out = host.cmd(f"tc qdisc replace dev {intf} parent 5:1 netem "
                       f"delay {delay}ms 2>&1; echo __rc=$?")
        if "__rc=0" in out:
            undo.append((host, f"tc qdisc replace dev {intf} parent 5:1 "
                               f"netem delay 5ms"))
        else:
            host.cmd(f"tc class change dev {intf} parent 5:0 classid 5:1 "
                     f"htb rate 300kbit burst 15k")
            undo.append((host, f"tc class change dev {intf} parent 5:0 "
                               f"classid 5:1 htb rate 10Mbit burst 15k"))
    try:
        yield
    finally:
        for host, cmd in undo:
            host.cmd(cmd)


# Everything run_demo.py can inject
DEMO_SCENARIOS = dict(SCENARIOS, latency_spike=latency_spike)
