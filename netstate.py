"""Reads the REAL state of the simulated routers: routes, firewall rules, link
state and delay. No Mininet import: pass in run(node, command) -> (exit code,
text), such as MininetExecutor.run.

The dashboard draws its network picture from this, never from a script, so what
you see on screen is what the routers are doing:

    route      ip route show <LAN>           -> primary or backup path
    drops      iptables -v -S FORWARD        -> which sources are dropped, and how many packets
    link       ip -br link show r1-eth1      -> is the primary link up
    delay      tc qdisc show dev r1-eth1     -> configured delay on that link
"""
import re
import time

from config import BACKUP_ROUTES, PRIMARY_ROUTES

LINK = ("r1", "r1-eth1")                      # the primary r1-r2 link, seen from r1
DROP_RE = re.compile(r"-s (\d+\.\d+\.\d+\.\d+)(?:/32)?\b(?:.*?-c (\d+) \d+)?.*-j DROP")
BLACKHOLE_RE = re.compile(r"from (\d+\.\d+\.\d+\.\d+)(?:/32)?\b.*blackhole")
DELAY_RE = re.compile(r"delay ([\d.]+)(us|ms|s)\b")


def _via(text):
    m = re.search(r"\bvia (\d+\.\d+\.\d+\.\d+)", text or "")
    return m.group(1) if m else None


def _drops(run, node):
    rc, out = run(node, "iptables -v -S FORWARD")
    if rc == 0:
        found = [(m.group(1), int(m.group(2)) if m.group(2) else None)
                 for m in map(DROP_RE.search, out.splitlines()) if m]
    else:                                      # no iptables: the policy-rule fallback
        _, rules = run(node, "ip rule show")
        found = [(m.group(1), None) for m in map(BLACKHOLE_RE.search, rules.splitlines()) if m]
    seen, drops = set(), []
    for src, pk in found:
        if src not in seen:
            seen.add(src)
            drops.append({"src": src, "packets": pk})
    return drops


def snapshot(run):
    """Plain JSON-safe dict. Never raises: a failed read shows as unknown."""
    primary = {n: v for n, _, v in PRIMARY_ROUTES}
    backup = {n: v for n, _, v in BACKUP_ROUTES}
    net = {"routers": {}, "path": "unknown", "read_at": time.time(),
           "primary": {"up": None, "delay_ms": None}}
    try:
        for node, prefix, _ in PRIMARY_ROUTES:
            _, out = run(node, f"ip route show {prefix}")
            via = _via(out)
            path = "backup" if via == backup[node] else "primary" if via == primary[node] else "unknown"
            net["routers"][node] = {"route": prefix, "via": via, "path": path,
                                    "drops": _drops(run, node)}
        net["path"] = net["routers"]["r1"]["path"]
        node, iface = LINK
        _, out = run(node, f"ip -br link show {iface}")
        toks = out.split()
        state = toks[1].upper() if len(toks) > 1 else ""
        net["primary"]["up"] = True if state == "UP" else False if state in ("DOWN", "LOWERLAYERDOWN") else None
        _, out = run(node, f"tc qdisc show dev {iface}")
        m = DELAY_RE.search(out)
        if m:
            net["primary"]["delay_ms"] = round(float(m.group(1)) * {"us": 0.001, "ms": 1, "s": 1000}[m.group(2)], 1)
    except Exception as e:                     # a reading problem must never stop the monitor
        net["error"] = str(e)[:100]
    return net
