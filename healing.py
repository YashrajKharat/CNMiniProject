"""The three healing actions, plus the bookkeeping that undoes them.

    BlockSource  quarantine a flooding or scanning source at its gateway router
    Reroute      move traffic from the primary link to the backup path via r3

Every action can be applied, verified and rolled back, and runs through an
Executor so the same code works on the live network or as a dry run that only
prints the commands.
"""
import ipaddress
import re
import time

from collector import parse_ping
from config import (BACKUP_ROUTES, GATEWAY_ROUTER, HEALTH_MAX_LATENCY_MS,
                    HEALTH_MAX_LOSS_PCT, PRIMARY_PROBE, PRIMARY_ROUTES,
                    PROTECTED_IPS, WEB_IP)


class ActionNotApplicable(Exception):
    """The healer cannot or must not act on this request."""


# ---------------------------------------------------------------- executors
class MininetExecutor:
    """Runs shell commands inside a Mininet node and returns (exit code, output)."""
    dry_run = False

    def __init__(self, net, on_run=None):
        self.net = net
        self.on_run = on_run          # called with (node, cmd, rc, output) after each command

    def run(self, node, cmd):
        out = self.net.get(node).cmd(f"{cmd}; echo __RC=$?")
        m = re.search(r"__RC=(\d+)\s*$", out)
        rc, text = (1, out.strip()) if not m else (int(m.group(1)), out[:m.start()].strip())
        if self.on_run:
            self.on_run(node, cmd, rc, text)
        return rc, text


class DryRunExecutor:
    """Records and prints commands without running them. Always succeeds."""
    dry_run = True

    def __init__(self, echo=True, on_run=None):
        self.log = []
        self.echo = echo
        self.on_run = on_run

    def run(self, node, cmd):
        self.log.append((node, cmd))
        if self.echo:
            print(f"      [dry run] {node}: {cmd}")
        if self.on_run:
            self.on_run(node, cmd, 0, "dry run: not executed")
        return 0, ""


# ------------------------------------------------------------------ actions
class BlockSource:
    """Drop everything from one source address at the router it connects to.

    The block goes on the router (FORWARD chain), not on the server, so the
    attack traffic never reaches the server's link. Falls back to a blackhole
    policy rule if the kernel has no iptables support.
    """
    kind = "block_source"

    def __init__(self, ip, reason):
        try:
            self.ip = str(ipaddress.IPv4Address(ip))
        except ValueError:
            raise ActionNotApplicable(f"'{ip}' is not a valid source address")
        self.reason = reason
        self.router = self._gateway(self.ip)
        self.backend = None

    @staticmethod
    def _gateway(ip):
        if ip in PROTECTED_IPS:
            raise ActionNotApplicable(
                f"{ip} is a protected address (server, router or probe host)")
        if ip.startswith(WEB_IP.rsplit(".", 1)[0] + "."):
            raise ActionNotApplicable(
                f"{ip} is on the same LAN as the server, so no router sees its "
                "traffic (a switch-level block would be needed)")
        for prefix, router in GATEWAY_ROUTER.items():
            if ip.startswith(prefix):
                return router
        raise ActionNotApplicable(f"no gateway router is known for {ip}")

    def describe(self):
        return f"block {self.ip} at {self.router} ({self.reason})"

    def _exists_cmd(self):
        if self.backend == "iptables":
            return f"iptables -C FORWARD -s {self.ip} -j DROP"
        return f'ip rule show | grep -qF "from {self.ip} "'

    def apply(self, ex):
        rc, _ = ex.run(self.router, "iptables -S FORWARD")
        self.backend = "iptables" if rc == 0 else "ip rule"
        if self.backend == "iptables":
            add = (f"{self._exists_cmd()} 2>/dev/null || "
                   f"iptables -I FORWARD 1 -s {self.ip} -j DROP")
        else:
            add = (f"{self._exists_cmd()} || "
                   f"ip rule add from {self.ip}/32 blackhole priority 100")
        rc, out = ex.run(self.router, add)
        if rc != 0:
            return False, f"command failed: {out}"
        if ex.run(self.router, self._exists_cmd())[0] != 0:
            return False, "rule was not found after adding it"
        return True, f"{self.backend} rule active on {self.router}"

    def rollback(self, ex):
        if self.backend == "iptables":
            cmd = (f"while iptables -C FORWARD -s {self.ip} -j DROP 2>/dev/null; "
                   f"do iptables -D FORWARD -s {self.ip} -j DROP; done")
        else:
            cmd = (f"while ip rule del from {self.ip}/32 priority 100 2>/dev/null; "
                   f"do :; done")
        rc, out = ex.run(self.router, cmd)
        gone = ex.dry_run or ex.run(self.router, self._exists_cmd())[0] != 0
        return rc == 0 and gone, "block removed" if gone else "rule is still present"

    def verify(self, sample, detection):
        """The attack is gone when the models see normal traffic again."""
        if not detection.abnormal:
            return True
        if detection.label == "unknown":
            is_scan_gone = sample.get("unique_ports_max", 1) <= 5
            is_flood_gone = float(sample.get("syn_ratio", 0)) < 0.3 and float(sample.get("pps", 0)) < 200
            is_loss_healthy = float(sample.get("loss_pct", 0)) <= 10.0 and float(sample.get("latency_ms", 0)) <= 50.0
            if is_scan_gone and is_flood_gone and is_loss_healthy:
                return True
        return False


class Reroute:
    """Send traffic through r3 instead of the direct r1-r2 link."""
    kind = "reroute"

    def __init__(self):
        self.saved = {}

    def describe(self):
        return "reroute r1<->r2 traffic via r3 (backup path)"

    def apply(self, ex):
        for node, prefix, _ in BACKUP_ROUTES:
            _, out = ex.run(node, f"ip route show {prefix}")
            line = out.strip().splitlines()[0] if out.strip() else ""
            self.saved[(node, prefix)] = re.sub(r"\blinkdown\b", "", line).strip()
        for node, prefix, via in BACKUP_ROUTES:
            rc, out = ex.run(node, f"ip route replace {prefix} via {via}")
            if rc != 0:
                return False, f"{node}: ip route replace failed: {out}"
        return True, "routes now use r3"

    def rollback(self, ex):
        ok = True
        for (node, prefix), old in self.saved.items():
            cmd = f"ip route replace {old}" if old else f"ip route del {prefix}"
            rc, _ = ex.run(node, cmd)
            ok = ok and (rc == 0 or not old)
        return ok, "previous routes restored" if ok else "could not restore old routes"

    def verify(self, sample, detection):
        """Service is back when probes get through again at a sane latency."""
        return (float(sample["loss_pct"]) <= HEALTH_MAX_LOSS_PCT
                and float(sample["latency_ms"]) <= HEALTH_MAX_LATENCY_MS)


# ------------------------------------------------------------------- healer
class Healer:
    """Applies actions and remembers what is currently changed.

    Keeps the list of active blocks (released automatically after block_ttl
    seconds, so a false alarm cannot quarantine a host forever) and whether
    traffic is on the backup path (moved back once the primary is healthy).
    """

    def __init__(self, executor, audit, block_ttl=600, failback_check_s=15):
        self.ex = executor
        self.audit = audit
        self.block_ttl = block_ttl
        self.failback_check_s = failback_check_s
        self.blocks = {}                 # ip -> (BlockSource, applied_at)
        self.reroute = None              # active Reroute action, if any
        self._last_failback_check = 0.0

    @property
    def dry_run(self):
        return self.ex.dry_run

    def apply(self, action, incident_id):
        ok, detail = action.apply(self.ex)
        self.audit.write("action_applied", incident=incident_id, action=action.kind,
                         what=action.describe(), ok=ok, detail=detail,
                         dry_run=self.dry_run)
        if ok and not self.dry_run:
            if action.kind == "block_source":
                self.blocks[action.ip] = (action, time.time())
            else:
                self.reroute = action
                # Wait a full interval before the first fail-back check. Right
                # after the reroute the primary link is idle, so a probe would
                # look healthy and flip traffic straight back onto a bad link.
                self._last_failback_check = time.time()
        return ok, detail

    def rollback(self, action, incident_id, why):
        ok, detail = action.rollback(self.ex)
        self.audit.write("rollback", incident=incident_id, action=action.kind,
                         what=action.describe(), ok=ok, detail=detail, why=why)
        if action.kind == "block_source":
            self.blocks.pop(action.ip, None)
        elif self.reroute is action:
            self.reroute = None
        return ok, detail

    def tick(self, now=None):
        """Housekeeping, called once per sample: expire blocks, try failback."""
        now = time.time() if now is None else now
        if self.block_ttl:
            for ip, (action, applied_at) in list(self.blocks.items()):
                if now - applied_at >= self.block_ttl:
                    ok, detail = action.rollback(self.ex)
                    self.blocks.pop(ip, None)
                    self.audit.write("block_expired", action=action.kind,
                                     what=action.describe(), ok=ok, detail=detail,
                                     ttl_s=self.block_ttl)
        if (self.reroute is not None and not self.dry_run
                and now - self._last_failback_check >= self.failback_check_s):
            self._last_failback_check = now
            self._try_failback()

    def _try_failback(self):
        node, target = PRIMARY_PROBE
        _, out = self.ex.run(node, f"ping -c 3 -i 0.2 -W 1 -q {target}")
        latency, loss = parse_ping(out)
        if loss > 0 or latency > HEALTH_MAX_LATENCY_MS:
            return
        for n, prefix, via in PRIMARY_ROUTES:
            self.ex.run(n, f"ip route replace {prefix} via {via}")
        self.reroute = None
        self.audit.write("failback", ok=True,
                         detail=f"primary link healthy (rtt {latency:.1f} ms), "
                                "traffic moved back to r1-r2")

    def cleanup(self):
        """Undo everything: release all blocks and restore the primary path."""
        for ip, (action, _) in list(self.blocks.items()):
            ok, detail = action.rollback(self.ex)
            self.audit.write("block_released", action=action.kind,
                             what=action.describe(), ok=ok, detail=detail)
        self.blocks.clear()
        if self.reroute is not None and not self.dry_run:
            for n, prefix, via in PRIMARY_ROUTES:
                self.ex.run(n, f"ip route replace {prefix} via {via}")
            self.audit.write("primary_restored", ok=True,
                             detail="routes set back to the primary path")
        self.reroute = None
