"""Shared constants for the Autonomous Network Engineer simulation.

This file has no Mininet import, so it can be loaded anywhere (collector,
ML code, dashboard) without needing root or Mininet installed.
"""
import os
import sys

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PROJECT_DIR, "data")
SNIFFER = os.path.join(PROJECT_DIR, "sniff_window.py")
WWW_DIR = "/tmp/ane_www"          # files served by the simulated web server
PYTHON = sys.executable           # same interpreter inside Mininet namespaces

# ---------------------------------------------------------------- addressing
#   LAN1 10.0.1.0/24 : h1 h2 h3 h4(attacker)  --- s1 --- r1
#   LAN2 10.0.2.0/24 : h5 h6 web              --- s2 --- r2
#   r1-r2 10.0.12.0/30  primary path
#   r1-r3 10.0.13.0/30  and  r3-r2 10.0.23.0/30  backup path (via r3)
WEB_IP = "10.0.2.100"

# host name -> (ip/prefix, default gateway)
HOSTS = {
    "h1": ("10.0.1.11/24", "10.0.1.1"),
    "h2": ("10.0.1.12/24", "10.0.1.1"),
    "h3": ("10.0.1.13/24", "10.0.1.1"),
    "h4": ("10.0.1.14/24", "10.0.1.1"),
    "h5": ("10.0.2.11/24", "10.0.2.1"),
    "h6": ("10.0.2.12/24", "10.0.2.1"),
    "web": (WEB_IP + "/24", "10.0.2.1"),
}
LAN1_HOSTS = ["h1", "h2", "h3", "h4"]
LAN2_HOSTS = ["h5", "h6", "web"]
CLIENTS = ["h1", "h2", "h3", "h5", "h6"]   # generate normal traffic
ATTACKER = "h4"                            # used for attacks in Week 2

ROUTERS = ["r1", "r2", "r3"]
# (router, interface, address)
ROUTER_ADDRS = [
    ("r1", "r1-eth0", "10.0.1.1/24"),
    ("r1", "r1-eth1", "10.0.12.1/30"),
    ("r1", "r1-eth2", "10.0.13.1/30"),
    ("r2", "r2-eth0", "10.0.2.1/24"),
    ("r2", "r2-eth1", "10.0.12.2/30"),
    ("r2", "r2-eth2", "10.0.23.1/30"),
    ("r3", "r3-eth0", "10.0.13.2/30"),
    ("r3", "r3-eth1", "10.0.23.2/30"),
]

# ------------------------------------------------------------ monitoring
PROBE_SRC = "h1"            # host that pings the web server for latency/loss
TARGET = "web"              # host whose inbound traffic we measure
TARGET_IFACE = "web-eth0"
PING_TIMEOUT_MS = 1000.0    # latency value used when every probe is lost

FEATURES = [
    "latency_ms",        # average RTT of 5 probe pings (1000 if all lost)
    "loss_pct",          # % of probe pings lost
    "throughput_mbps",   # inbound traffic at the web server
    "pps",               # inbound packets per second at the web server
    "syn_ratio",         # SYN-only packets / all TCP packets (inbound)
    "unique_ports_max",  # most distinct dest ports probed by one source
    "arp_rate",          # ARP packets per second seen at the web server
]
# top_src_ip is metadata (not a model feature): the source sending the most
# SYNs in the window. The healing engine uses it to know who to block.
COLUMNS = ["timestamp", "label"] + FEATURES + ["top_src_ip"]

# ------------------------------------------------------- healing (Week 3)
MODELS_DIR = os.path.join(PROJECT_DIR, "models")
AUDIT_LOG = os.path.join(DATA_DIR, "audit.jsonl")

LINK_CAPACITY_MBPS = 10      # primary and backup router links
SATURATION_FRACTION = 0.7    # inbound load above this share of capacity means
                             # the link is full of traffic, not broken
REROUTE_ON_CONGESTION = True # Apply autonomous reroute on congestion


# The router every packet from a LAN crosses first: the place to block a source
GATEWAY_ROUTER = {"10.0.1.": "r1", "10.0.2.": "r2"}

# (router, destination LAN, next hop) for each path. Both directions switch
# together, otherwise replies would still use the old path.
PRIMARY_ROUTES = [("r1", "10.0.2.0/24", "10.0.12.2"),
                  ("r2", "10.0.1.0/24", "10.0.12.1")]
BACKUP_ROUTES = [("r1", "10.0.2.0/24", "10.0.13.2"),
                 ("r2", "10.0.1.0/24", "10.0.23.2")]
PRIMARY_PROBE = ("r1", "10.0.12.2")   # ping used to see if the primary is healthy

# Addresses the healer must never block: the server, every router address and
# the host that sends the latency probes. Add any other critical host here.
ROUTER_IPS = [addr.split("/")[0] for _, _, addr in ROUTER_ADDRS]
PROTECTED_IPS = frozenset([WEB_IP, HOSTS[PROBE_SRC][0].split("/")[0]] + ROUTER_IPS)

# What counts as a degraded service. A sample past either limit means users are
# hurt even when the models cannot name the cause. The same limits decide
# whether a reroute worked (healing.Reroute.verify).
HEALTH_MAX_LOSS_PCT = 10
HEALTH_MAX_LATENCY_MS = 100
