"""Tests for the decision engine and healing actions. No Mininet, no sudo needed:

    python test_healing.py

A fake executor records the commands instead of running them, so these check
the logic (confirmation, modes, verification, rollback, safety rules) only.
The real commands are exercised by  sudo venv/bin/python run_demo.py.
"""
import os, sys, tempfile, json, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import decision, healing
from audit import AuditLog
from detector import Detection
from healing import BlockSource, Reroute, ActionNotApplicable, Healer, DryRunExecutor

decision.time.sleep = lambda s: None   # no real waiting in tests

def row(**kw):
    r = dict(latency_ms=11.0, loss_pct=0.0, throughput_mbps=0.03, pps=40.0, syn_ratio=0.1,
             unique_ports_max=1, arp_rate=0.0, top_src_ip="")
    r.update(kw); return r

NORMAL = Detection(False, "normal", 0.1)
def flagged(label): return Detection(True, label, -0.2)

class FakeEx:
    """Records commands. `fail` = substrings that make a command return rc 1."""
    dry_run = False
    def __init__(self, routes=None, fail=(), iptables=True):
        self.cmds, self.fail, self.iptables = [], fail, iptables
        self.rules, self.routes = set(), routes or {}
    def run(self, node, cmd):
        self.cmds.append((node, cmd))
        if any(f in cmd for f in self.fail): return 1, "forced failure"
        if cmd.startswith("iptables -S"): return (0, "") if self.iptables else (1, "no iptables")
        if cmd.startswith("ip route show"):
            return 0, self.routes.get((node, cmd.split()[-1]), "")
        if "iptables -C" in cmd and "||" not in cmd and "while" not in cmd:
            ip = cmd.split("-s ")[1].split()[0]
            return (0, "") if (node, ip) in self.rules else (1, "")
        if "iptables -I FORWARD" in cmd:
            self.rules.add((node, cmd.split("-s ")[1].split()[0])); return 0, ""
        if cmd.startswith("while iptables"):
            self.rules = {r for r in self.rules if r[1] not in cmd}; return 0, ""
        if "ip rule add" in cmd:          # combined "grep || ip rule add": the add branch runs
            self.rules.add((node, cmd.split("ip rule add from ")[1].split("/")[0])); return 0, ""
        if "ip rule show" in cmd and "grep" in cmd:
            ip = cmd.split("from ")[1].split()[0]
            return (0, "") if (node, ip) in self.rules else (1, "")
        if cmd.startswith("while ip rule del"):
            self.rules = {r for r in self.rules if r[1] not in cmd}; return 0, ""
        return 0, ""

class Env:
    def __init__(self, mode="auto", ex=None, feed=None, **kw):
        self.tmp = tempfile.mkdtemp()
        self.audit = AuditLog(os.path.join(self.tmp, "audit.jsonl"))
        self.ex = ex or FakeEx()
        self.healer = Healer(self.ex, self.audit)
        self.feed = list(feed or [])
        self.engine = decision.DecisionEngine(self.healer, self.audit, self._next, mode=mode, **kw)
    def _next(self):
        return self.feed.pop(0) if self.feed else (row(), NORMAL)
    def events(self):
        with open(self.audit.path) as f:
            return [json.loads(l)["event"] for l in f]
    def push(self, samples):
        out = None
        for s, d in samples:
            r = self.engine.process(s, d)
            out = r or out
        return out

FLOOD = (row(pps=1500, syn_ratio=0.5, throughput_mbps=0.6, top_src_ip="10.0.1.14"), flagged("syn_flood"))
FAIL = (row(latency_ms=1000, loss_pct=100, pps=12, throughput_mbps=0.01), flagged("link_failure"))

class T(unittest.TestCase):
    def setUp(self): decision.say = lambda m: None

    def test_single_flagged_sample_does_nothing(self):
        e = Env(); self.assertIsNone(e.push([FLOOD, (row(), NORMAL), FLOOD, (row(), NORMAL)]))
        self.assertEqual(e.ex.cmds, [])

    def test_flood_blocked_and_verified(self):
        e = Env(feed=[(row(), NORMAL), (row(), NORMAL)])
        inc = e.push([FLOOD, FLOOD])
        self.assertEqual((inc.status, inc.action), ("resolved", "block_source"))
        self.assertIn(("r1", "10.0.1.14"), e.ex.rules)
        self.assertIn("10.0.1.14", e.healer.blocks)
        self.assertGreater(inc.recovered_at, 0)

    def test_failed_verification_rolls_back(self):
        e = Env(feed=[(row(), flagged("syn_flood"))] * 3)
        inc = e.push([FLOOD, FLOOD])
        self.assertEqual(inc.status, "rolled_back")
        self.assertNotIn(("r1", "10.0.1.14"), e.ex.rules)
        self.assertEqual(e.healer.blocks, {})
        self.assertIn("rollback", e.events())

    def test_rolled_back_incident_not_retried_until_clear(self):
        e = Env(feed=[(row(), flagged("syn_flood"))] * 3)
        e.push([FLOOD, FLOOD])
        n = len(e.ex.cmds)
        self.assertIsNone(e.push([FLOOD, FLOOD, FLOOD]))      # suppressed
        self.assertEqual(len(e.ex.cmds), n)
        e.push([(row(), NORMAL)] * 3)                          # clear_n=3 normals
        e.feed = [(row(), NORMAL)] * 3
        self.assertIsNotNone(e.push([FLOOD, FLOOD]))           # new incident now

    def test_monitor_mode_only_logs(self):
        e = Env(mode="monitor"); inc = e.push([FLOOD, FLOOD])
        self.assertEqual(inc.status, "observed"); self.assertEqual(e.ex.cmds, [])

    def test_approval_declined_and_granted(self):
        e = Env(mode="approval"); e.engine.approver = lambda a, i: False
        self.assertEqual(e.push([FLOOD, FLOOD]).status, "declined"); self.assertEqual(e.ex.cmds, [])
        e = Env(mode="approval", feed=[(row(), NORMAL)] * 2); e.engine.approver = lambda a, i: True
        self.assertEqual(e.push([FLOOD, FLOOD]).status, "resolved")

    def test_dry_run_changes_nothing(self):
        e = Env(); e.healer.ex = DryRunExecutor(echo=False)
        inc = e.push([FLOOD, FLOOD])
        self.assertEqual(inc.status, "dry_run"); self.assertTrue(e.healer.ex.log)
        self.assertEqual(e.healer.blocks, {}); self.assertEqual(e.ex.cmds, [])

    def test_reroute_verified_by_health_not_model(self):
        # backup path is slower (40 ms) and the model still calls it abnormal: still a success
        slow_ok = (row(latency_ms=42, loss_pct=0), flagged("unknown"))
        e = Env(feed=[slow_ok, slow_ok]); inc = e.push([FAIL, FAIL])
        self.assertEqual((inc.status, inc.action), ("resolved", "reroute"))
        self.assertIsNotNone(e.healer.reroute)

    def test_reroute_not_helping_rolls_back_to_saved_routes(self):
        ex = FakeEx(routes={("r1", "10.0.2.0/24"): "10.0.2.0/24 via 10.0.12.2 dev r1-eth1"})
        e = Env(ex=ex, feed=[(row(latency_ms=1000, loss_pct=100), flagged("link_failure"))] * 3)
        inc = e.push([FAIL, FAIL]); self.assertEqual(inc.status, "rolled_back")
        self.assertIn(("r1", "ip route replace 10.0.2.0/24 via 10.0.12.2 dev r1-eth1"), ex.cmds)
        self.assertIn(("r2", "ip route del 10.0.1.0/24"), ex.cmds)   # nothing saved -> removed
        self.assertIsNone(e.healer.reroute)

    def test_congestion_saturated_link_is_advisory(self):
        import config
        orig = getattr(config, "REROUTE_ON_CONGESTION", False)
        config.REROUTE_ON_CONGESTION = False
        try:
            c = (row(latency_ms=1200, loss_pct=70, throughput_mbps=9.8, pps=480), flagged("congestion"))
            e = Env(); inc = e.push([c, c])
            self.assertEqual((inc.status, inc.action), ("no_action", "")); self.assertEqual(e.ex.cmds, [])
            self.assertIn("rerouting would only move", inc.detail)
        finally:
            config.REROUTE_ON_CONGESTION = orig


    def test_congestion_not_saturated_reroutes(self):
        c = (row(latency_ms=300, loss_pct=0, throughput_mbps=0.05), flagged("congestion"))
        e = Env(feed=[(row(latency_ms=45), NORMAL)] * 2); inc = e.push([c, c])
        self.assertEqual((inc.status, inc.action), ("resolved", "reroute"))

    def test_unknown_label_is_ignored(self):
        e = Env(); self.assertIsNone(e.push([(row(), flagged("unknown"))] * 5)); self.assertEqual(e.ex.cmds, [])

    def test_protected_and_same_lan_sources_refused(self):
        for ip in ("10.0.2.100", "10.0.1.11", "10.0.1.1", "10.0.2.12", "999.1.1.1", "8.8.8.8", "10.0.1.14; reboot"):
            with self.assertRaises(ActionNotApplicable, msg=ip): BlockSource(ip, "x")
        self.assertEqual(BlockSource("10.0.1.14", "x").router, "r1")
        e = Env(); inc = e.push([(row(top_src_ip="10.0.1.11"), flagged("syn_flood"))] * 2)
        self.assertEqual(inc.status, "no_action"); self.assertEqual(e.ex.cmds, [])

    def test_no_source_identified(self):
        e = Env(); inc = e.push([(row(top_src_ip=""), flagged("port_scan"))] * 2)
        self.assertEqual(inc.status, "no_action")

    def test_apply_failure_rolls_back_and_reports(self):
        e = Env(ex=FakeEx(fail=("iptables -I",))); inc = e.push([FLOOD, FLOOD])
        self.assertEqual(inc.status, "failed")

    def test_fallback_to_ip_rule_without_iptables(self):
        e = Env(ex=FakeEx(iptables=False), feed=[(row(), NORMAL)] * 2); inc = e.push([FLOOD, FLOOD])
        self.assertEqual(inc.status, "resolved")
        self.assertTrue(any("ip rule add from 10.0.1.14/32 blackhole" in c for _, c in e.ex.cmds))

    def test_cleanup_releases_blocks_and_restores_primary(self):
        e = Env(feed=[(row(), NORMAL)] * 2); e.push([FLOOD, FLOOD]); e.healer.reroute = Reroute()
        e.healer.cleanup()
        self.assertEqual(e.ex.rules, set()); self.assertIsNone(e.healer.reroute)
        self.assertIn(("r1", "ip route replace 10.0.2.0/24 via 10.0.12.2"), e.ex.cmds)

    def test_block_ttl_expires(self):
        e = Env(feed=[(row(), NORMAL)] * 2); e.healer.block_ttl = 60
        e.push([FLOOD, FLOOD]); applied = e.healer.blocks["10.0.1.14"][1]
        e.healer.tick(applied + 30); self.assertIn("10.0.1.14", e.healer.blocks)
        e.healer.tick(applied + 61); self.assertEqual(e.healer.blocks, {}); self.assertEqual(e.ex.rules, set())

    def test_audit_log_tells_the_story(self):
        e = Env(feed=[(row(), NORMAL)] * 2); e.push([FLOOD, FLOOD])
        ev = e.events()
        for needed in ("incident_confirmed", "action_planned", "action_applied", "verify_sample", "incident_closed"):
            self.assertIn(needed, ev)

    def test_failback_waits_for_healthy_primary(self):
        class PingEx(FakeEx):
            healthy = False
            def run(self, node, cmd):
                if cmd.startswith("ping"):
                    self.cmds.append((node, cmd))
                    return 0, ("5 packets transmitted, 5 received, 0% packet loss\nrtt min/avg/max/mdev = 9/10/11/1 ms"
                               if self.healthy else "3 packets transmitted, 3 received, 0% packet loss\nrtt min/avg/max/mdev = 190/200/210/1 ms")
                return super().run(node, cmd)
        ex = PingEx(); e = Env(ex=ex); e.healer.reroute = Reroute(); e.healer.failback_check_s = 0
        e.healer.tick(1); self.assertIsNotNone(e.healer.reroute)        # degraded primary: stay on backup
        ex.healthy = True; e.healer.tick(2); self.assertIsNone(e.healer.reroute)
        self.assertIn("failback", e.events())

    def test_no_failback_check_straight_after_a_reroute(self):
        class IdlePrimary(FakeEx):
            """The primary link answers pings well because traffic just left it."""
            def run(self, node, cmd):
                if cmd.startswith("ping"):
                    self.cmds.append((node, cmd))
                    return 0, ("3 packets transmitted, 3 received, 0% packet loss\n"
                               "rtt min/avg/max/mdev = 9/10/11/1 ms")
                return super().run(node, cmd)
        e = Env(ex=IdlePrimary()); t = decision.time.time()
        e.healer.apply(Reroute(), 1)
        e.healer.tick(t + 1)                                   # too soon: no probe, no failback
        self.assertIsNotNone(e.healer.reroute)
        self.assertFalse(any(c.startswith("ping") for _, c in e.ex.cmds))
        e.healer.tick(t + e.healer.failback_check_s + 1)       # a full interval later: probe runs
        self.assertIsNone(e.healer.reroute)

    # ---- a problem the Random Forest cannot name, while users are hurting
    def test_unknown_with_slow_service_is_treated_as_degraded_link(self):
        slow = (row(latency_ms=300, loss_pct=0, throughput_mbps=0.02), flagged("unknown"))
        on_backup = (row(latency_ms=42, loss_pct=0), flagged("unknown"))  # slower path, model still unsure
        e = Env(feed=[on_backup, on_backup]); inc = e.push([slow, slow])
        self.assertEqual((inc.label, inc.status, inc.action), ("degraded_link", "resolved", "reroute"))
        self.assertIsNotNone(e.healer.reroute)

    def test_unknown_with_lossy_service_also_counts(self):
        lossy = (row(latency_ms=20, loss_pct=40), flagged("unknown"))
        e = Env(feed=[(row(), NORMAL)] * 2)
        self.assertEqual(e.push([lossy, lossy]).label, "degraded_link")

    def test_unknown_with_healthy_service_is_still_ignored(self):
        # an Isolation Forest false alarm: odd score, but latency and loss are fine
        e = Env()
        self.assertIsNone(e.push([(row(latency_ms=40, loss_pct=0), flagged("unknown"))] * 5))
        self.assertEqual(e.ex.cmds, [])

    def test_degraded_link_on_a_full_link_is_advisory(self):
        import config
        orig = getattr(config, "REROUTE_ON_CONGESTION", False)
        config.REROUTE_ON_CONGESTION = False
        try:
            full = (row(latency_ms=300, throughput_mbps=9.0), flagged("unknown"))
            e = Env(); inc = e.push([full, full])
            self.assertEqual((inc.label, inc.status, inc.action), ("degraded_link", "no_action", ""))
            self.assertEqual(e.ex.cmds, [])
        finally:
            config.REROUTE_ON_CONGESTION = orig


    def test_degraded_link_not_rerouted_again_while_on_backup(self):
        slow = (row(latency_ms=300), flagged("unknown"))
        e = Env(); e.healer.reroute = Reroute()
        inc = e.push([slow, slow])
        self.assertEqual(inc.status, "no_action"); self.assertIn("already on the backup", inc.detail)
        self.assertEqual(e.ex.cmds, [])

    def test_degraded_link_rolls_back_if_reroute_does_not_help(self):
        slow = (row(latency_ms=300), flagged("unknown"))
        e = Env(feed=[slow] * 3); inc = e.push([slow, slow])
        self.assertEqual((inc.label, inc.status), ("degraded_link", "rolled_back"))
        self.assertIsNone(e.healer.reroute)

    # ---- the models flip between labels for one slow or broken path
    def test_flipping_path_labels_still_confirm_together(self):
        slow = dict(latency_ms=300, loss_pct=0, throughput_mbps=0.02)
        unnamed, cong = (row(**slow), flagged("unknown")), (row(**slow), flagged("congestion"))
        e = Env(feed=[(row(), NORMAL)] * 2)
        inc = e.push([unnamed, cong])                    # two different labels, one problem
        self.assertEqual((inc.status, inc.action), ("resolved", "reroute"))

    def test_most_common_label_names_the_incident(self):
        slow = dict(latency_ms=300, loss_pct=0, throughput_mbps=0.02)
        e = Env(confirm_n=3, feed=[(row(), NORMAL)] * 2)
        inc = e.push([(row(**slow), flagged("unknown")), (row(**slow), flagged("congestion")),
                      (row(**slow), flagged("unknown"))])
        self.assertEqual(inc.label, "degraded_link")

    def test_an_attack_label_never_merges_with_a_path_problem(self):
        slow = (row(latency_ms=300), flagged("unknown"))
        e = Env()
        self.assertIsNone(e.push([FLOOD, slow, FLOOD, slow]))   # alternating: never two in a row
        self.assertEqual(e.ex.cmds, [])

    def test_failed_reroute_is_not_retried_under_another_path_label(self):
        slow = (row(latency_ms=300), flagged("unknown"))
        e = Env(feed=[slow] * 3); self.assertEqual(e.push([slow, slow]).status, "rolled_back")
        n = len(e.ex.cmds)
        self.assertIsNone(e.push([FAIL, FAIL, (row(latency_ms=300), flagged("congestion"))]))
        self.assertEqual(len(e.ex.cmds), n)

if __name__ == "__main__":
    unittest.main(verbosity=2)
