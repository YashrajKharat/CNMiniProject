"""Mininet topology for the Autonomous Network Engineer project.

Two LANs joined by three Linux routers. r1-r2 is the primary path; r1-r3-r2
is the backup. Only the primary routes are installed at start, so when the
primary link fails the healer has to add the backup route (Week 3).

Needs root and Mininet:  sudo venv/bin/python run_baseline.py
"""
import os
import time

from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import Node, OVSBridge
from mininet.nodelib import LinuxBridge

from config import (HOSTS, LAN1_HOSTS, LAN2_HOSTS, ROUTER_ADDRS, ROUTERS)


class LinuxRouter(Node):
    """A Mininet node with IP forwarding switched on."""

    def config(self, **params):
        super().config(**params)
        self.cmd("sysctl -w net.ipv4.ip_forward=1")

    def terminate(self):
        self.cmd("sysctl -w net.ipv4.ip_forward=0")
        super().terminate()


def build_network(primary_bw=10, primary_delay="5ms",
                  backup_bw=10, backup_delay="10ms"):
    """Create (but do not start) the network."""
    # Test-only switches for machines without Open vSwitch / netem support
    # (for example a CI container). Normal use needs neither variable.
    switch = LinuxBridge if os.environ.get("ANE_SWITCH") == "lxbr" else OVSBridge
    if os.environ.get("ANE_NO_NETEM"):
        primary_delay = backup_delay = None
    net = Mininet(controller=None, switch=switch, link=TCLink,
                  autoSetMacs=True)

    s1 = net.addSwitch("s1")
    s2 = net.addSwitch("s2")
    r1 = net.addHost("r1", cls=LinuxRouter, ip=None)
    r2 = net.addHost("r2", cls=LinuxRouter, ip=None)
    r3 = net.addHost("r3", cls=LinuxRouter, ip=None)

    for name in LAN1_HOSTS:
        ip, gw = HOSTS[name]
        host = net.addHost(name, ip=ip, defaultRoute=f"via {gw}")
        net.addLink(host, s1)
    net.addLink(s1, r1, intfName2="r1-eth0")

    for name in LAN2_HOSTS:
        ip, gw = HOSTS[name]
        host = net.addHost(name, ip=ip, defaultRoute=f"via {gw}")
        net.addLink(host, s2)
    net.addLink(s2, r2, intfName2="r2-eth0")

    # Router interconnects (bandwidth-limited so congestion is possible)
    net.addLink(r1, r2, intfName1="r1-eth1", intfName2="r2-eth1",
                bw=primary_bw, delay=primary_delay)
    net.addLink(r1, r3, intfName1="r1-eth2", intfName2="r3-eth0",
                bw=backup_bw, delay=backup_delay)
    net.addLink(r2, r3, intfName1="r2-eth2", intfName2="r3-eth1",
                bw=backup_bw, delay=backup_delay)
    return net


def configure_routing(net):
    """Assign router addresses and install the primary static routes."""
    for node_name, intf, addr in ROUTER_ADDRS:
        node = net.get(node_name)
        node.cmd(f"ip addr add {addr} dev {intf}")
        node.cmd(f"ip link set dev {intf} up")

    for name in ROUTERS:
        node = net.get(name)
        node.cmd("sysctl -w net.ipv4.conf.all.rp_filter=0")
        node.cmd("sysctl -w net.ipv4.conf.default.rp_filter=0")
        for intf in node.intfNames():
            node.cmd(f"sysctl -w net.ipv4.conf.{intf}.rp_filter=0")

    use_primary(net)
    # r3 only forwards when the backup path is in use
    net.get("r3").cmd("ip route replace 10.0.1.0/24 via 10.0.13.1")
    net.get("r3").cmd("ip route replace 10.0.2.0/24 via 10.0.23.1")


def start_network(**kwargs):
    net = build_network(**kwargs)
    net.start()
    configure_routing(net)
    time.sleep(1)          # let the OVS bridges settle
    return net


def check_connectivity(net):
    """Ping between all hosts. Returns the percentage dropped."""
    hosts = [net.get(name) for name in HOSTS]
    return net.ping(hosts, timeout=2)


# ----------------------------------------------------- fault / route helpers
# Week 3's healer will wrap these; for now they let you test by hand.

def primary_link_down(net):
    net.configLinkStatus("r1", "r2", "down")


def primary_link_up(net):
    net.configLinkStatus("r1", "r2", "up")


def use_primary(net):
    net.get("r1").cmd("ip route replace 10.0.2.0/24 via 10.0.12.2")
    net.get("r2").cmd("ip route replace 10.0.1.0/24 via 10.0.12.1")


def use_backup(net):
    net.get("r1").cmd("ip route replace 10.0.2.0/24 via 10.0.13.2")
    net.get("r2").cmd("ip route replace 10.0.1.0/24 via 10.0.23.2")
