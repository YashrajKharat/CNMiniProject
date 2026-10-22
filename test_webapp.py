"""Tests for the web app (no Mininet, no root): python test_webapp.py"""
import json
import os
import re
import shutil
import tempfile
import time
import unittest

import control
from webapp import create_app, Network, db
from webapp.security import Vault, parse_devices, is_local_path

PW = "correct horse 9"
SECRET_PW = "S3cretDevicePw!"


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.app = create_app(self.dir, testing=True)
        self.c = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def token(self):
        html = self.c.get("/login").get_data(as_text=True)
        m = re.search(r'name="csrf" value="([^"]+)"', html) or re.search(r'name="csrf" content="([^"]+)"', html)
        if not m:
            m = re.search(r'<meta name="csrf" content="([^"]+)"', html)
        return m.group(1)

    def tok(self):
        with self.c.session_transaction() as s:
            return s.get("csrf") or ""

    def setup_admin(self):
        self.c.get("/setup")
        return self.c.post("/setup", data={"csrf": self.tok(), "username": "admin",
                                           "password": PW, "password2": PW})

    def login(self, pw=PW, user="admin", follow=False):
        self.c.get("/login")
        return self.c.post("/login", data={"csrf": self.tok(), "username": user, "password": pw},
                           follow_redirects=follow)

    def logged_in(self):
        self.setup_admin()
        self.assertEqual(self.login().status_code, 302)

    def post_json(self, url, body):
        return self.c.post(url, json=body, headers={"X-CSRF-Token": self.tok()})

    def add_network(self, **over):
        data = {"csrf": self.tok(), "name": "Lab", "subnet": "10.0.1.0/24", "devices": "",
                "ssh_user": "admin", "ssh_password": SECRET_PW}
        data.update(over)
        return self.c.post("/networks", data=data, follow_redirects=True)

    def monitor_alive(self, **extra):
        st = {"updated": time.time(), "started": time.time(), "state": "monitoring", "mode": "auto",
              "dry_run": False, "fault": None, "on_backup": False, "blocked": [],
              "last": {"latency_ms": 11.0, "loss_pct": 0, "throughput_mbps": 0.02, "pps": 40,
                       "syn_ratio": 0.1, "label": "normal"}}
        st.update(extra)
        control.write_json(control.paths(self.dir)["status"], st)


class AuthTests(Base):
    def test_first_visit_goes_to_setup_and_only_one_admin(self):
        self.assertIn("/setup", self.c.get("/").headers["Location"])
        self.assertEqual(self.setup_admin().status_code, 302)
        # setup is closed once an administrator exists
        self.assertIn("/login", self.c.get("/setup").headers["Location"])
        r = self.c.post("/setup", data={"csrf": self.tok(), "username": "evil", "password": PW,
                                        "password2": PW})
        self.assertEqual(r.status_code, 302)
        from webapp import User
        with self.app.app_context():
            self.assertEqual(User.query.count(), 1)

    def test_weak_or_mismatched_password_rejected(self):
        self.c.get("/setup")
        r = self.c.post("/setup", data={"csrf": self.tok(), "username": "admin",
                                        "password": "short", "password2": "short"})
        self.assertIn("at least 8", r.get_data(as_text=True))
        r = self.c.post("/setup", data={"csrf": self.tok(), "username": "admin",
                                        "password": PW, "password2": PW + "x"})
        self.assertIn("do not match", r.get_data(as_text=True))

    def test_password_is_hashed(self):
        self.setup_admin()
        from webapp import User
        with self.app.app_context():
            h = User.query.first().password_hash
        self.assertNotIn(PW, h)
        self.assertTrue(h.startswith(("scrypt:", "pbkdf2:")))

    def test_wrong_password_and_unknown_user(self):
        self.setup_admin()
        self.assertEqual(self.login("nope").status_code, 401)
        self.assertEqual(self.login(PW, user="ghost").status_code, 401)
        self.assertEqual(self.login().status_code, 302)

    def test_lockout_after_five_failures(self):
        self.setup_admin()
        for _ in range(5):
            self.assertEqual(self.login("bad").status_code, 401)
        self.assertEqual(self.login("bad").status_code, 429)
        self.assertEqual(self.login(PW).status_code, 429)      # even the right one waits

    def test_pages_and_api_need_login(self):
        self.setup_admin()
        for url in ("/dashboard", "/networks", "/reports"):
            r = self.c.get(url)
            self.assertEqual(r.status_code, 302)
            self.assertIn("/login", r.headers["Location"])
        for url in ("/api/status", "/api/metrics", "/api/incidents", "/api/audit"):
            self.assertEqual(self.c.get(url).status_code, 401)
        self.assertEqual(self.post_json("/api/mode", {"mode": "auto"}).status_code, 401)

    def test_csrf_required_on_post(self):
        self.setup_admin()
        self.c.get("/login")
        r = self.c.post("/login", data={"username": "admin", "password": PW})   # no token
        self.assertEqual(r.status_code, 400)
        self.logged_in_after_setup = self.login()
        r = self.c.post("/api/mode", json={"mode": "auto"})                    # no header
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.post_json("/api/mode", {"mode": "auto"}).status_code, 200)

    def test_open_redirect_blocked(self):
        self.setup_admin()
        self.c.get("/login")
        r = self.c.post("/login?next=https://evil.example/", data={
            "csrf": self.tok(), "username": "admin", "password": PW})
        self.assertIn("/dashboard", r.headers["Location"])
        self.assertTrue(is_local_path("/networks"))
        for bad in ("//evil.example", "http://evil.example", "/\\evil.example", ""):
            self.assertFalse(is_local_path(bad))

    def test_logout_needs_post_and_ends_session(self):
        self.logged_in()
        self.assertEqual(self.c.get("/logout").status_code, 405)
        self.c.post("/logout", data={"csrf": self.tok()})
        self.assertEqual(self.c.get("/api/status").status_code, 401)

    def test_security_headers(self):
        r = self.c.get("/login")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        self.assertNotIn("script-src 'unsafe-inline'", r.headers["Content-Security-Policy"])


class NetworkTests(Base):
    def test_dashboard_needs_a_network(self):
        self.logged_in()
        r = self.c.get("/dashboard", follow_redirects=True)
        self.assertIn("Add the network", r.get_data(as_text=True))

    def test_credentials_are_encrypted_at_rest(self):
        self.logged_in()
        r = self.add_network(devices="10.0.1.11 h1\n10.0.2.100 web")
        # the second device is outside 10.0.1.0/24, so nothing was saved
        self.assertIn("outside", r.get_data(as_text=True))
        r = self.add_network(devices="10.0.1.11 h1\n10.0.1.1 r1")
        self.assertIn("stored encrypted", r.get_data(as_text=True))
        self.assertNotIn(SECRET_PW, r.get_data(as_text=True))
        with self.app.app_context():
            n = Network.query.one()
            self.assertTrue(n.active)
            self.assertNotIn(SECRET_PW, n.cred_enc)
            self.assertEqual(self.app.vault.unseal(n.cred_enc),
                             {"username": "admin", "password": SECRET_PW})
        # nothing on disk contains the plain password
        for root, _, files in os.walk(self.dir):
            for f in files:
                with open(os.path.join(root, f), "rb") as fh:
                    self.assertNotIn(SECRET_PW.encode(), fh.read(), f)

    def test_key_file_is_private(self):
        self.logged_in()
        for name in ("secret.key", "flask_secret"):
            mode = os.stat(os.path.join(self.dir, name)).st_mode & 0o777
            expected = 0o666 if os.name == "nt" else 0o600
            self.assertEqual(mode, expected, name)

    def test_tampered_or_foreign_token_does_not_decrypt(self):
        v1 = Vault(self.dir)
        tok = v1.seal({"password": "x"})
        other = tempfile.mkdtemp()
        try:
            self.assertIsNone(Vault(other).unseal(tok))
        finally:
            shutil.rmtree(other, ignore_errors=True)
        self.assertIsNone(v1.unseal(tok[:-4] + "AAAA"))

    def test_validation_messages(self):
        self.logged_in()
        cases = [({"name": ""}, "name"), ({"subnet": "banana"}, "subnet"),
                 ({"subnet": "10.0.0.0/8"}, "/16"), ({"subnet": "fe80::/64"}, "IPv4"),
                 ({"devices": "10.0.1.300"}, "valid IP"), ({"devices": "10.0.1.5\n10.0.1.5"}, "twice"),
                 ({"ssh_user": ""}, "username"), ({"ssh_password": ""}, "password")]
        for over, word in cases:
            r = self.add_network(**over)
            self.assertIn(word, r.get_data(as_text=True), over)
        with self.app.app_context():
            self.assertEqual(Network.query.count(), 0)

    def test_discovery_finds_simulated_devices(self):
        self.logged_in()
        self.add_network()                       # no device list: discover the subnet
        html = self.c.get("/dashboard").get_data(as_text=True)
        for ip in ("10.0.1.11", "10.0.1.14", "10.0.1.1"):
            self.assertIn(ip, html)
        self.assertNotIn("10.0.2.100", html)
        self.add_network(name="Extra", subnet="10.0.1.0/24", devices="10.0.1.99 ghost")
        self.assertIn("Not in the simulation", self.c.get("/networks").get_data(as_text=True))

    def test_activate_and_delete(self):
        self.logged_in()
        self.add_network(name="A")
        self.add_network(name="B", subnet="10.0.2.0/24")
        with self.app.app_context():
            a, b = [n.id for n in Network.query.order_by(Network.id)]
        self.c.post(f"/networks/{b}/activate", data={"csrf": self.tok()})
        with self.app.app_context():
            self.assertEqual([n.name for n in Network.query.filter_by(active=True)], ["B"])
        self.c.post(f"/networks/{b}/delete", data={"csrf": self.tok()})
        with self.app.app_context():
            self.assertEqual([(n.name, n.active) for n in Network.query.all()], [("A", True)])
        self.assertEqual(self.c.post("/networks/999/delete", data={"csrf": self.tok()}).status_code, 404)

    def test_names_are_escaped(self):
        self.logged_in()
        self.add_network(name="<script>alert(1)</script>")
        html = self.c.get("/networks").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_parse_devices(self):
        self.assertEqual(parse_devices("10.0.0.1 a\n\n# note\n10.0.0.2"), [("10.0.0.1", "a"), ("10.0.0.2", "")])
        with self.assertRaises(ValueError):
            parse_devices("\n".join(f"10.1.{i // 250}.{i % 250 + 1}" for i in range(300)))


class ApiTests(Base):
    def setUp(self):
        super().setUp()
        self.logged_in()
        self.add_network()

    def test_status_offline_when_monitor_never_ran(self):
        st = self.c.get("/api/status").get_json()
        self.assertEqual(st["state"], "offline")

    def test_status_goes_offline_when_stale(self):
        self.monitor_alive(updated=time.time() - 60)
        self.assertEqual(self.c.get("/api/status").get_json()["state"], "offline")
        self.monitor_alive()
        self.assertEqual(self.c.get("/api/status").get_json()["state"], "monitoring")

    def test_mode_validation_and_effect(self):
        self.assertEqual(self.post_json("/api/mode", {"mode": "nope"}).status_code, 400)
        self.assertEqual(self.post_json("/api/mode", {"mode": "approval"}).status_code, 200)
        self.assertEqual(control.MonitorChannel(self.dir).mode("auto"), "approval")

    def test_inject_needs_running_monitor_and_known_scenario(self):
        self.assertEqual(self.post_json("/api/inject", {"scenario": "syn_flood"}).status_code, 409)
        self.monitor_alive()
        self.assertEqual(self.post_json("/api/inject", {"scenario": "rm -rf /"}).status_code, 400)
        self.assertEqual(self.post_json("/api/inject", {"scenario": "syn_flood"}).status_code, 200)
        chan = control.MonitorChannel(self.dir)
        self.assertEqual(chan.take_injection(), "syn_flood")
        self.assertIsNone(chan.take_injection())                  # only once
        self.post_json("/api/stop-fault", {})
        self.assertTrue(chan.wants_stop_fault())

    def test_second_fault_is_refused_while_one_runs_or_queued(self):
        self.monitor_alive()
        self.assertEqual(self.post_json("/api/inject", {"scenario": "syn_flood"}).status_code, 200)
        r = self.post_json("/api/inject", {"scenario": "link_failure"})       # still queued
        self.assertEqual(r.status_code, 409)
        control.MonitorChannel(self.dir).take_injection()
        self.monitor_alive(fault="syn_flood")
        r = self.post_json("/api/inject", {"scenario": "link_failure"})       # running
        self.assertEqual(r.status_code, 409)
        self.assertIn("already running", r.get_json()["error"])
        self.monitor_alive(fault=None)
        self.assertEqual(self.post_json("/api/inject", {"scenario": "link_failure"}).status_code, 200)

    def test_stale_fault_request_never_starts_late(self):
        p = control.paths(self.dir)["control"]
        control.write_json(p, {"inject": {"scenario": "syn_flood", "requested": time.time() - 120}})
        self.assertIsNone(control.MonitorChannel(self.dir).take_injection())
        self.assertNotIn("inject", control.read_json(p))

    def test_approval_round_trip(self):
        self.monitor_alive()
        p = control.paths(self.dir)
        ident = "1-123"
        control.write_json(p["approval"], {"id": ident, "incident": 1, "problem": "syn_flood",
                                           "what": "block 10.0.1.14", "asked": time.time(),
                                           "expires": time.time() + 30})
        st = self.c.get("/api/status").get_json()
        self.assertEqual(st["pending_approval"]["id"], ident)
        self.assertEqual(self.post_json("/api/approval", {"id": "wrong", "approved": True}).status_code, 409)
        self.assertEqual(self.post_json("/api/approval", {"id": ident, "approved": "yes"}).status_code, 400)
        self.assertEqual(self.post_json("/api/approval", {"id": ident, "approved": True}).status_code, 200)
        self.assertEqual(control.read_json(p["response"])["approved"], True)

    def test_expired_approval_cannot_be_answered(self):
        p = control.paths(self.dir)
        control.write_json(p["approval"], {"id": "x", "expires": time.time() - 1})
        self.assertEqual(self.post_json("/api/approval", {"id": "x", "approved": True}).status_code, 409)
        self.assertIsNone(self.c.get("/api/status").get_json().get("pending_approval"))

    def test_metrics_and_audit_endpoints(self):
        p = control.paths(self.dir)
        with open(p["metrics"], "w") as f:
            for i in range(50):
                f.write(json.dumps({"epoch": 1000 + i, "latency_ms": 10 + i, "loss_pct": 0, "pps": 40,
                                    "label": "normal", "abnormal": False, "secret": "x"}) + "\n")
            f.write("{broken\n")
        rows = self.c.get("/api/metrics?n=10").get_json()
        self.assertEqual(len(rows), 9)                      # broken line skipped
        self.assertNotIn("secret", rows[0])
        self.assertEqual(len(self.c.get("/api/metrics?n=999999").get_json()), 50)
        with open(p["audit"], "w") as f:
            f.write(json.dumps({"time": "t", "epoch": 1, "event": "verify_sample"}) + "\n")
            f.write(json.dumps({"time": "t", "epoch": 2, "event": "action_applied", "what": "x"}) + "\n")
        self.assertEqual([r["event"] for r in self.c.get("/api/audit").get_json()], ["action_applied"])

    def test_incidents_built_from_audit(self):
        from audit import AuditLog
        a = AuditLog(control.paths(self.dir)["audit"])
        t = time.time()
        a.write("fault_injected", scenario="syn_flood")
        a.write("incident_confirmed", incident=1, problem="syn_flood", samples=2, evidence={}, mode="auto")
        a.write("incident_closed", incident=1, problem="syn_flood", status="resolved", action="block_source",
                detail="verified", first_flag_at=t + 4, confirmed_at=t + 9, recovered_at=t + 19)
        inc = self.c.get("/api/incidents").get_json()
        self.assertEqual(len(inc), 1)
        self.assertEqual((inc[0]["problem"], inc[0]["status"]), ("syn_flood", "resolved"))
        self.assertAlmostEqual(inc[0]["mttd"], 9, delta=1)
        self.assertAlmostEqual(inc[0]["mttr"], 19, delta=1)

    def test_dashboard_page_renders_controls(self):
        html = self.c.get("/dashboard").get_data(as_text=True)
        for text in ("Watch only", "Ask me first", "Fix automatically", "Latency spike", "End fault"):
            self.assertIn(text, html)


class ReportTests(Base):
    def setUp(self):
        super().setUp()
        self.logged_in()

    def test_generate_list_and_download(self):
        r = self.c.post("/reports/generate", data={"csrf": self.tok()}, follow_redirects=True)
        self.assertIn("Report created", r.get_data(as_text=True))
        names = os.listdir(os.path.join(self.dir, "reports"))
        self.assertTrue(any(n.endswith(".html") for n in names))
        html_name = next(n for n in names if n.endswith(".html"))
        r = self.c.get("/reports/" + html_name)
        self.assertEqual(r.status_code, 200)
        self.assertIn("Autonomous Network Engineer: Report", r.get_data(as_text=True))
        pdfs = [n for n in names if n.endswith(".pdf")]
        if pdfs:
            r = self.c.get("/reports/" + pdfs[0])
            self.assertTrue(r.data.startswith(b"%PDF"))
            self.assertIn("attachment", r.headers["Content-Disposition"])

    def test_report_names_cannot_escape_the_folder(self):
        for bad in ("..%2Fapp.db", "report_1.html", "report_20240101_000000.txt", "secret.key"):
            self.assertEqual(self.c.get("/reports/" + bad).status_code, 404, bad)

    def test_report_numbers_match_the_logs(self):
        from audit import AuditLog
        import reporting
        a = AuditLog(control.paths(self.dir)["audit"])
        t = time.time()
        a.write("fault_injected", scenario="link_failure")
        a.write("incident_confirmed", incident=1, problem="link_failure", samples=2, evidence={}, mode="auto")
        a.write("incident_closed", incident=1, problem="link_failure", status="resolved", action="reroute",
                detail="ok", first_flag_at=t + 4, confirmed_at=t + 9, recovered_at=t + 19)
        with open(control.paths(self.dir)["metrics"], "w") as f:
            for i, (lat, loss) in enumerate([(10, 0), (10, 0), (500, 100), (40, 0)]):
                f.write(json.dumps({"epoch": t - 10 + i, "latency_ms": lat, "loss_pct": loss,
                                    "abnormal": loss > 0, "fault": None}) + "\n")
        rep = reporting.build_report(self.dir)
        self.assertEqual(len(rep["incidents"]), 1)
        self.assertEqual(rep["uptime_pct"], 75.0)               # 3 of 4 samples healthy
        self.assertEqual(rep["samples"], 4)
        self.assertTrue(any("backup path" in r for r in rep["recommendations"]))

    def test_report_uses_the_browsers_time_zone(self):
        import reporting
        from audit import AuditLog
        a = AuditLog(control.paths(self.dir)["audit"])
        a.write("fault_injected", scenario="link_failure")
        self.c.set_cookie("tz", "Asia/Kolkata")
        self.c.get("/reports")                                   # any page remembers it
        self.assertEqual(reporting.get_tz(self.dir).key, "Asia/Kolkata")
        rep = reporting.build_report(self.dir)
        self.assertEqual(rep["tz"], "IST")
        from datetime import datetime
        from zoneinfo import ZoneInfo
        now_ist = datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M")
        self.assertTrue(rep["audit_tail"][0]["time"].startswith(now_ist[:13]))
        self.assertIn("(IST)", reporting.render_html(rep))
        self.c.set_cookie("tz", "Not/AZone")                     # junk is ignored
        self.c.get("/reports")
        self.assertEqual(reporting.get_tz(self.dir).key, "Asia/Kolkata")

    def test_report_covers_only_the_chosen_period(self):
        from audit import AuditLog
        a = AuditLog(control.paths(self.dir)["audit"])
        now = time.time()
        for k, (age, name) in enumerate([(7200, "old"), (60, "new")], 1):
            a.write("incident_closed", incident=1, problem="syn_flood", status="resolved", action="block_source",
                    detail=name, first_flag_at=now - age, confirmed_at=now - age + 5, recovered_at=now - age + 15)
            # make the record's own timestamp match its age
        lines = open(control.paths(self.dir)["audit"]).read().splitlines()
        import json as _j
        recs = [_j.loads(x) for x in lines]
        recs[0]["epoch"], recs[1]["epoch"] = now - 7200, now - 60
        open(control.paths(self.dir)["audit"], "w").write("\n".join(_j.dumps(r) for r in recs) + "\n")
        self.monitor_alive(started=now - 600)
        self.c.post("/reports/generate", data={"csrf": self.tok(), "period": "session"})
        self.c.post("/reports/generate", data={"csrf": self.tok(), "period": "all"})
        html = self.c.get("/reports").get_data(as_text=True)
        self.assertIn("Since the monitor started", html)
        self.assertIn("All recorded data", html)
        import reporting
        self.assertEqual(len(reporting.build_report(self.dir, since=now - 600)["incidents"]), 1)
        self.assertEqual(len(reporting.build_report(self.dir)["incidents"]), 2)

    def test_incident_numbers_are_unique_inside_a_report(self):
        from audit import AuditLog
        import reporting
        a = AuditLog(control.paths(self.dir)["audit"])
        for _ in range(3):                      # three monitor runs, each numbering from 1
            a.write("incident_closed", incident=1, problem="link_failure", status="resolved",
                    action="reroute", detail="", first_flag_at=time.time(), confirmed_at=time.time(),
                    recovered_at=time.time())
        self.assertEqual([i["id"] for i in reporting.build_report(self.dir)["incidents"]], [1, 2, 3])

    def test_empty_report_is_valid(self):
        import reporting
        rep = reporting.build_report(self.dir)
        self.assertIsNone(rep["uptime_pct"])
        self.assertIn("No incidents", " ".join(rep["recommendations"]))
        self.assertIn("No incidents in this period", reporting.render_html(rep))

    def test_scheduler_is_off_by_default_and_runs_when_asked(self):
        self.assertIsNone(self.app.scheduler)
        app = create_app(self.dir, report_every_min=5, testing=True)
        self.assertEqual(app.scheduler.get_job("report").trigger.interval.total_seconds(), 300)


class ControlTests(unittest.TestCase):
    def test_atomic_writes_and_publish(self):
        d = tempfile.mkdtemp()
        try:
            from detector import Detection
            from healing import Healer, DryRunExecutor
            from audit import AuditLog
            chan = control.MonitorChannel(d)
            healer = Healer(DryRunExecutor(), AuditLog(os.path.join(d, "audit.jsonl")))
            chan.publish({"latency_ms": 12.0, "loss_pct": 0, "pps": 40, "label": "live"},
                         Detection(False, "normal", 0.1), "auto", healer)
            st = control.current_status(d)
            self.assertEqual(st["state"], "monitoring")
            self.assertEqual(st["last"]["label"], "normal")      # the model's label, not "live"
            self.assertFalse(any(f.endswith(".tmp") for f in os.listdir(d)))
            chan.offline()
            self.assertEqual(control.current_status(d)["state"], "offline")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_metric_log_is_trimmed(self):
        d = tempfile.mkdtemp()
        try:
            from detector import Detection
            from healing import Healer, DryRunExecutor
            from audit import AuditLog
            old = control.MAX_METRIC_LINES
            control.MAX_METRIC_LINES = 20
            try:
                chan = control.MonitorChannel(d)
                healer = Healer(DryRunExecutor(), AuditLog(os.path.join(d, "audit.jsonl")))
                for i in range(35):
                    chan.publish({"latency_ms": i}, Detection(False, "normal", 0.0), "auto", healer)
                lines = open(control.paths(d)["metrics"]).read().splitlines()
                self.assertLessEqual(len(lines), 20)
                self.assertEqual(json.loads(lines[-1])["latency_ms"], 34)
            finally:
                control.MAX_METRIC_LINES = old
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_approver_waits_for_answer_and_times_out(self):
        d = tempfile.mkdtemp()
        try:
            import threading
            from healing import Healer, DryRunExecutor, Reroute
            from audit import AuditLog
            from decision import Incident
            chan = control.MonitorChannel(d)
            healer = Healer(DryRunExecutor(), AuditLog(os.path.join(d, "audit.jsonl")))
            ask = chan.approver(lambda: healer, timeout=3)
            inc = Incident(1, "link_failure", 0, 0, {})

            def answer():
                for _ in range(40):
                    p = control.read_json(control.paths(d)["approval"])
                    if p:
                        control.answer_approval(p["id"], True, d)
                        return
                    time.sleep(0.05)
            th = threading.Thread(target=answer)
            th.start()
            self.assertTrue(ask(Reroute(), inc, timeout=3))
            th.join()
            self.assertFalse(os.path.exists(control.paths(d)["approval"]))   # cleaned up
            t0 = time.time()
            self.assertFalse(ask(Reroute(), inc, timeout=1))                  # nobody answers
            self.assertLess(time.time() - t0, 3)
        finally:
            shutil.rmtree(d, ignore_errors=True)



class NetStateTests(unittest.TestCase):
    """The dashboard picture comes from netstate.snapshot, so parsing must be right."""

    @staticmethod
    def runner(via="10.0.12.2", drop=True, link="UP", delay="delay 5ms"):
        def run(node, cmd):
            if cmd.startswith("ip route show 10.0.2"):
                return 0, f"10.0.2.0/24 via {via} dev r1-eth1"
            if cmd.startswith("ip route show 10.0.1"):
                return 0, "10.0.1.0/24 via 10.0.12.1 dev r2-eth1"
            if cmd.startswith("iptables"):
                rule = "\n-A FORWARD -s 10.0.1.14/32 -c 4821 289260 -j DROP" if drop and node == "r1" else ""
                return 0, "-P FORWARD ACCEPT" + rule
            if cmd.startswith("ip -br"):
                return 0, f"r1-eth1@if5 {link} 10.0.12.1/30"
            if cmd.startswith("tc"):
                return 0, f"qdisc netem 10: root {delay}"
            return 1, ""
        return run

    def test_normal_with_block(self):
        import netstate
        n = netstate.snapshot(self.runner())
        self.assertEqual(n["path"], "primary")
        self.assertEqual(n["routers"]["r1"]["drops"], [{"src": "10.0.1.14", "packets": 4821}])
        self.assertEqual(n["routers"]["r2"]["drops"], [])
        self.assertEqual(n["primary"], {"up": True, "delay_ms": 5.0})

    def test_backup_and_link_down(self):
        import netstate
        n = netstate.snapshot(self.runner(via="10.0.13.2", drop=False, link="DOWN", delay="delay 150ms"))
        self.assertEqual(n["path"], "backup")
        self.assertEqual(n["primary"], {"up": False, "delay_ms": 150.0})
        self.assertEqual(n["routers"]["r1"]["drops"], [])

    def test_ip_rule_fallback_and_errors(self):
        import netstate
        def run(node, cmd):
            if cmd.startswith("iptables"):
                return 1, "not found"
            if cmd == "ip rule show":
                return 0, "100: from 10.0.1.14 lookup blackhole\n0: from all lookup local"
            return 1, ""
        self.assertEqual(netstate.snapshot(run)["routers"]["r1"]["drops"], [{"src": "10.0.1.14", "packets": None}])
        def broken_run(n, c):
            raise RuntimeError("simulated error")
        self.assertIn("error", netstate.snapshot(broken_run))

if __name__ == "__main__":
    unittest.main(verbosity=2)
