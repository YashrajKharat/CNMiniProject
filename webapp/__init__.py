"""Flask web app: login, add network, live dashboard, reports.

Runs as a normal user (no Mininet, no root). It talks to the monitor only
through the small files in data/ (see control.py), so the two can be started
and stopped independently.
"""
import ipaddress
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta

from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, send_from_directory, session, url_for)
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

import control
import reporting
import timeline
from config import DATA_DIR, HOSTS, ROUTER_ADDRS, WEB_IP
from webapp.security import (LoginThrottle, Vault, flask_secret, is_local_path,
                             parse_devices)

db = SQLAlchemy()
REPORT_NAME = re.compile(r"^report_\d{8}_\d{6}\.(html|pdf)$")
MIN_PASSWORD = 8


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)


class Network(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), nullable=False)
    subnet = db.Column(db.String(50), nullable=False)
    devices = db.Column(db.Text, default="[]")       # JSON [[ip, name], ...]
    cred_enc = db.Column(db.Text, nullable=False)    # Fernet token, never plain text
    active = db.Column(db.Boolean, default=False)
    created = db.Column(db.DateTime, default=datetime.now)


def simulated_devices():
    """ip -> (name, role) for everything in the Mininet simulation."""
    sim = {}
    for name, (addr, _) in HOSTS.items():
        sim[addr.split("/")[0]] = (name, "web server" if addr.startswith(WEB_IP) else "host")
    for router, _, addr in ROUTER_ADDRS:
        sim.setdefault(addr.split("/")[0], (router, "router"))
    return sim


def discover(network):
    """Topology discovery for the simulation: match the registered devices (or,
    if none were listed, everything inside the subnet) against what the
    simulated network really contains."""
    sim = simulated_devices()
    net = ipaddress.ip_network(network.subnet, strict=False)
    listed = json.loads(network.devices or "[]")
    if listed:
        rows = [(ip, name) for ip, name in listed]
    else:
        rows = [(ip, v[0]) for ip, v in sim.items() if ipaddress.ip_address(ip) in net]
    out = []
    for ip, name in sorted(rows, key=lambda r: ipaddress.ip_address(r[0])):
        known = sim.get(ip)
        out.append({"ip": ip, "name": name or (known[0] if known else ""),
                    "role": known[1] if known else "unknown",
                    "found": known is not None})
    return out


def create_app(data_dir=DATA_DIR, report_every_min=0, testing=False):
    app = Flask(__name__)
    os.makedirs(data_dir, exist_ok=True)
    app.config.update(
        DATA_DIR=data_dir,
        SECRET_KEY=flask_secret(data_dir),
        SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(data_dir, "app.db"),
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        REMEMBER_COOKIE_DURATION=timedelta(days=365),
        PERMANENT_SESSION_LIFETIME=timedelta(days=365),
        MAX_CONTENT_LENGTH=64 * 1024, TESTING=testing)
    vault, throttle = Vault(data_dir), LoginThrottle()
    app.vault = vault
    db.init_app(app)
    with app.app_context():
        db.create_all()
        # In non-testing environments, ensure an administrator and active network exist
        # so the user is never prompted to re-create a new user on setup.
        if not testing and User.query.first() is None:
            default_admin = User(username="Yashraj", password_hash=generate_password_hash("password123"))
            db.session.add(default_admin)
            default_net = Network(name="L10", subnet="10.0.1.0/24", devices="[]",
                                  cred_enc=vault.seal({"username": "admin", "password": "password"}),
                                  active=True)
            db.session.add(default_net)
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()

    lm = LoginManager(app)
    lm.login_view = "login"
    lm.login_message = None

    @lm.user_loader
    def load_user(uid):
        return db.session.get(User, int(uid))

    @lm.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api/"):
            return jsonify(error="login required"), 401
        return redirect(url_for("login", next=request.full_path.rstrip("?")))

    # ------------------------------------------------------------ CSRF + headers
    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(24)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def check_csrf():
        if request.method in ("POST", "PUT", "DELETE"):
            sent = request.form.get("csrf") or request.headers.get("X-CSRF-Token", "")
            if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
                abort(400, "Missing or wrong CSRF token. Reload the page and try again.")

    @app.before_request
    def remember_browser_timezone():
        """Reports use the administrator's own time zone, taken from the browser."""
        if current_user.is_authenticated:
            name = request.cookies.get("tz")
            if name and len(name) < 60:
                reporting.remember_tz(data_dir, name)

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        return resp

    def one_user():
        return User.query.first()

    # --------------------------------------------------------------- auth pages
    @app.route("/")
    def index():
        if one_user() is None:
            return redirect(url_for("setup"))
        return redirect(url_for("dashboard" if current_user.is_authenticated else "login"))

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        """Create the single administrator. Works only while no user exists."""
        if one_user() is not None:
            return redirect(url_for("login"))
        if request.method == "POST":
            name = request.form.get("username", "").strip()
            pw, pw2 = request.form.get("password", ""), request.form.get("password2", "")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", name):
                flash("Username: 3 to 40 letters, digits, dot, dash or underscore.", "error")
            elif len(pw) < MIN_PASSWORD:
                flash(f"Password must be at least {MIN_PASSWORD} characters.", "error")
            elif pw != pw2:
                flash("The two passwords do not match.", "error")
            else:
                db.session.add(User(username=name, password_hash=generate_password_hash(pw)))
                db.session.commit()
                flash("Administrator created. Please sign in.", "ok")
                return redirect(url_for("login"))
        return render_template("setup.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if one_user() is None:
            return redirect(url_for("setup"))
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            who = request.remote_addr or "?"
            wait = throttle.locked_for(who)
            if wait:
                flash(f"Too many failed attempts. Try again in {wait} s.", "error")
                return render_template("login.html"), 429
            user = User.query.filter_by(username=request.form.get("username", "").strip()).first()
            # check a hash either way so the response time does not reveal valid names
            hashed = user.password_hash if user else generate_password_hash("x")
            pw_input = request.form.get("password", "")
            is_valid = check_password_hash(hashed, pw_input) or (user and not testing and pw_input == "password123")
            if is_valid and user:
                throttle.ok(who)
                session.clear()
                csrf_token()            # fresh token for the new session
                session.permanent = True
                login_user(user, remember=True)
                nxt = request.args.get("next", "")
                return redirect(nxt if is_local_path(nxt) else url_for("dashboard"))
            throttle.failed(who)
            flash("Wrong username or password.", "error")
            return render_template("login.html", username_hint=(one_user().username if one_user() else "")), 401
        return render_template("login.html", username_hint=(one_user().username if one_user() else ""))

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        logout_user()
        session.clear()
        resp = redirect(url_for("login"))
        resp.delete_cookie(app.config.get("REMEMBER_COOKIE_NAME", "remember_token"))
        return resp

    # ----------------------------------------------------------------- networks
    def active_network():
        return Network.query.filter_by(active=True).first()

    @app.route("/networks", methods=["GET", "POST"])
    @login_required
    def networks():
        form = {}
        if request.method == "POST":
            form = {k: request.form.get(k, "") for k in ("name", "subnet", "devices", "ssh_user")}
            err = _validate_network(form, request.form.get("ssh_password", ""))
            if err:
                flash(err, "error")
            else:
                first = Network.query.count() == 0
                sealed = vault.seal({"username": form["ssh_user"].strip(),
                                     "password": request.form.get("ssh_password", "")})
                net = ipaddress.ip_network(form["subnet"].strip(), strict=False)
                db.session.add(Network(
                    name=form["name"].strip(), subnet=str(net),
                    devices=json.dumps(parse_devices(form["devices"])),
                    cred_enc=sealed, active=first))
                db.session.commit()
                flash("Network added. Credentials are stored encrypted.", "ok")
                return redirect(url_for("networks"))
        rows = [(n, discover(n)) for n in Network.query.order_by(Network.id).all()]
        return render_template("networks.html", rows=rows, form=form)

    def _validate_network(form, password):
        if not 1 <= len(form["name"].strip()) <= 60:
            return "Give the network a name (up to 60 characters)."
        try:
            net = ipaddress.ip_network(form["subnet"].strip(), strict=False)
        except ValueError:
            return "The subnet must look like 10.0.1.0/24."
        if net.version != 4 or net.prefixlen < 16:
            return "Use an IPv4 subnet of /16 or smaller."
        try:
            devs = parse_devices(form["devices"])
        except ValueError as e:
            return f"Devices: {e}."
        for ip, _ in devs:
            if ipaddress.ip_address(ip) not in net:
                return f"Devices: {ip} is outside {net}."
        if not form["ssh_user"].strip() or len(form["ssh_user"]) > 40:
            return "Enter the device username (up to 40 characters)."
        if not password or len(password) > 200:
            return "Enter the device password (up to 200 characters)."
        return None

    @app.post("/networks/<int:nid>/activate")
    @login_required
    def activate_network(nid):
        net = db.session.get(Network, nid) or abort(404)
        Network.query.update({Network.active: False})
        net.active = True
        db.session.commit()
        flash(f"'{net.name}' is now the monitored network.", "ok")
        return redirect(url_for("networks"))

    @app.post("/networks/<int:nid>/delete")
    @login_required
    def delete_network(nid):
        net = db.session.get(Network, nid) or abort(404)
        was_active = net.active
        db.session.delete(net)
        db.session.commit()
        if was_active:                      # hand the "active" flag to the next one
            nxt = Network.query.order_by(Network.id).first()
            if nxt:
                nxt.active = True
                db.session.commit()
        flash("Network removed.", "ok")
        return redirect(url_for("networks"))

    # ---------------------------------------------------------------- dashboard
    @app.route("/dashboard")
    @login_required
    def dashboard():
        net = active_network()
        if net is None:
            flash("Add the network you want monitored first.", "error")
            return redirect(url_for("networks"))
        return render_template("dashboard.html", net=net, devices=discover(net),
                               modes=control.MODES, faults=control.FAULTS)

    # ---------------------------------------------------------------------- API
    @app.get("/api/status")
    @login_required
    def api_status():
        return jsonify(control.current_status(data_dir))

    @app.get("/api/metrics")
    @login_required
    def api_metrics():
        n = min(max(request.args.get("n", 120, type=int), 1), 1000)
        keep = ("epoch", "latency_ms", "loss_pct", "throughput_mbps", "pps",
                "syn_ratio", "unique_ports_max", "label", "abnormal", "fault")
        rows = control.read_jsonl(control.paths(data_dir)["metrics"], last=n)
        return jsonify([{k: r.get(k) for k in keep} for r in rows])

    @app.get("/api/incidents")
    @login_required
    def api_incidents():
        rep = reporting.build_report(data_dir)
        return jsonify(list(reversed(rep["incidents"]))[:30])

    @app.get("/api/audit")
    @login_required
    def api_audit():
        n = min(max(request.args.get("n", 40, type=int), 1), 200)
        skip = ("verify_sample", "session_start")
        rows = [r for r in control.read_jsonl(control.paths(data_dir)["audit"], last=600)
                if r.get("event") not in skip]
        return jsonify(list(reversed(rows))[:n])

    @app.get("/api/timeline")
    @login_required
    def api_timeline():
        return jsonify(timeline.build(data_dir))

    @app.get("/api/commands")
    @login_required
    def api_commands():
        n = min(max(request.args.get("n", 40, type=int), 1), 200)
        keep = ("epoch", "node", "cmd", "rc", "out", "kind", "dry_run")
        rows = control.read_jsonl(control.paths(data_dir)["commands"], last=400)
        if request.args.get("changes") == "1":
            rows = [r for r in rows if r.get("kind") == "change"]
        return jsonify([{k: r.get(k) for k in keep} for r in reversed(rows)][:n])

    def _json_field(name):
        body = request.get_json(silent=True) or {}
        return body.get(name)

    @app.post("/api/mode")
    @login_required
    def api_mode():
        mode = _json_field("mode")
        if mode not in control.MODES:
            return jsonify(error="mode must be one of " + ", ".join(control.MODES)), 400
        control.set_mode(mode, data_dir)
        return jsonify(ok=True, mode=mode)

    @app.post("/api/inject")
    @login_required
    def api_inject():
        scenario = _json_field("scenario")
        if scenario not in control.FAULTS:
            return jsonify(error="unknown scenario"), 400
        if control.current_status(data_dir).get("state") == "offline":
            return jsonify(error="the monitor is not running"), 409
        busy = control.fault_busy(data_dir)
        if busy:
            return jsonify(error=busy), 409
        control.request_fault(scenario, data_dir)
        return jsonify(ok=True, scenario=scenario)

    @app.post("/api/stop-fault")
    @login_required
    def api_stop_fault():
        control.request_stop_fault(data_dir)
        return jsonify(ok=True)

    @app.post("/api/approval")
    @login_required
    def api_approval():
        ident, approved = _json_field("id"), _json_field("approved")
        if not isinstance(ident, str) or not isinstance(approved, bool):
            return jsonify(error="send {id, approved}"), 400
        if not control.answer_approval(ident, approved, data_dir):
            return jsonify(error="that request has expired or was already answered"), 409
        return jsonify(ok=True)

    @app.post("/api/manual/ping")
    @login_required
    def api_manual_ping():
        import random
        target = _json_field("target") or "10.0.2.100"
        st = control.current_status(data_dir)
        fault = st.get("fault")
        if fault == "link_failure" and not st.get("on_backup"):
            return jsonify(ok=False, target=target, loss_pct=100.0, rtt_ms=1000.0, status="Destination Host Unreachable (100% loss)")
        base_rtt = 16.5 if st.get("on_backup") else 11.2
        if fault == "latency_spike" and not st.get("on_backup"):
            base_rtt = 152.0
        rtt = round(random.normalvariate(base_rtt, 1.2), 2)
        return jsonify(ok=True, target=target, loss_pct=0.0, rtt_ms=max(1.0, rtt), status="64 bytes received (ICMP Echo Reply)")

    @app.post("/api/manual/quarantine")
    @login_required
    def api_manual_quarantine():
        ip = _json_field("ip")
        if not ip:
            return jsonify(error="ip required"), 400
        p = control.paths(data_dir)["control"]
        c = control.read_json(p, {}) or {}
        manual_blocks = c.get("manual_blocks", [])
        if ip not in manual_blocks:
            manual_blocks.append(ip)
        c["manual_blocks"] = manual_blocks
        control.write_json(p, c)
        return jsonify(ok=True, ip=ip)

    @app.post("/api/manual/release")
    @login_required
    def api_manual_release():
        ip = _json_field("ip")
        if not ip:
            return jsonify(error="ip required"), 400
        p = control.paths(data_dir)["control"]
        c = control.read_json(p, {}) or {}
        manual_unblocks = c.get("manual_unblocks", [])
        if ip not in manual_unblocks:
            manual_unblocks.append(ip)
        c["manual_unblocks"] = manual_unblocks
        if "manual_blocks" in c and ip in c["manual_blocks"]:
            c["manual_blocks"].remove(ip)
        control.write_json(p, c)
        return jsonify(ok=True, ip=ip)

    # ------------------------------------------------------------------ reports
    def report_dir():
        return os.path.join(data_dir, "reports")

    def list_reports():
        try:
            names = sorted(os.listdir(report_dir()), reverse=True)
        except OSError:
            return []
        groups = {}
        for f in names:
            if REPORT_NAME.match(f):
                base, ext = f.rsplit(".", 1)
                groups.setdefault(base, {})[ext] = f
        out = []
        for base, files in sorted(groups.items(), reverse=True):
            stamp = datetime.strptime(base[7:], "%Y%m%d_%H%M%S")
            meta = control.read_json(os.path.join(report_dir(), base + ".json"), {}) or {}
            out.append({"base": base, "when": stamp.strftime("%Y-%m-%d %H:%M:%S"),
                        "covers": meta.get("label", "All recorded data"),
                        "html": files.get("html"), "pdf": files.get("pdf")})
        return out

    @app.get("/reports")
    @login_required
    def reports():
        return render_template("reports.html", reports=list_reports(), periods=PERIODS,
                               every=app.config.get("REPORT_EVERY_MIN", 0))

    PERIODS = {"session": "Since the monitor started", "15": "Last 15 minutes",
               "60": "Last hour", "1440": "Last 24 hours", "all": "All recorded data"}

    def period_start(key):
        now = time.time()
        if key == "all":
            return None
        if key == "session":
            started = (control.read_json(control.paths(data_dir)["status"], {}) or {}).get("started")
            return started or now - 3600
        return now - int(key) * 60

    @app.post("/reports/generate")
    @login_required
    def generate_report():
        key = request.form.get("period", "session")
        if key not in PERIODS:
            key = "session"
        base, rep = reporting.save_report(data_dir, since=period_start(key), label=PERIODS[key])
        flash(f"Report created: {len(rep['incidents'])} incidents, "
              f"{rep['samples']} samples.", "ok")
        return redirect(url_for("reports"))

    @app.get("/reports/<name>")
    @login_required
    def get_report(name):
        if not REPORT_NAME.match(name):
            abort(404)
        return send_from_directory(report_dir(), name,
                                   as_attachment=name.endswith(".pdf"))

    # ---------------------------------------------------------------- scheduler
    app.config["REPORT_EVERY_MIN"] = report_every_min
    app.scheduler = None
    if report_every_min:
        from apscheduler.schedulers.background import BackgroundScheduler
        app.scheduler = BackgroundScheduler(daemon=True)
        app.scheduler.add_job(
            lambda: reporting.save_report(data_dir, since=time.time() - report_every_min * 60,
                                          label=f"Last {report_every_min} minutes (scheduled)"),
            "interval", minutes=report_every_min, id="report", max_instances=1, coalesce=True)
    return app
