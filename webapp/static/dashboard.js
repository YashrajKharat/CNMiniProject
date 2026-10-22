(function () {
  "use strict";
  var CSRF = document.querySelector('meta[name="csrf"]').content;
  var BLUE = "#00e5ff", ORANGE = "#ef4444", AMBER = "#f59e0b";
  var LABELS = {normal: "Normal", syn_flood: "SYN flood", port_scan: "Port scan",
    link_failure: "Link failure", congestion: "Congestion", degraded_link: "Slow link",
    unknown: "Unrecognised"};
  var STATES = {monitoring: "Monitoring", offline: "Monitor is not running",
    waiting_for_approval: "Waiting for your approval"};
  var MODE_HELP = {
    monitor: "Detects and logs problems. Changes nothing.",
    approval: "Detects problems and asks you before every fix. No answer in 30 seconds counts as no.",
    auto: "Detects problems, applies the fix, checks it worked and undoes it if it did not."};
  var EVENTS = {incident_confirmed: "Problem confirmed", action_planned: "Fix planned",
    action_applied: "Fix applied", action_rolled_back: "Fix undone", action_released: "Fix released",
    approval_requested: "Approval asked", approval_result: "Approval answered",
    incident_closed: "Incident closed", fault_injected: "Fault started",
    fault_removed: "Fault ended", failback: "Back on primary path",
    block_released: "Block released", failback_check: "Probe check"};

  function $(id) { return document.getElementById(id); }
  function td(text) { var c = document.createElement("td"); c.textContent = text; return c; }
  function fill(tbody, rows, cols, emptyText) {
    tbody.replaceChildren();
    if (!rows.length) {
      var tr = document.createElement("tr"), c = td(emptyText);
      c.colSpan = cols; tr.appendChild(c); tbody.appendChild(tr); return;
    }
    rows.forEach(function (cells) {
      var tr = document.createElement("tr");
      cells.forEach(function (t) { tr.appendChild(td(t)); });
      tbody.appendChild(tr);
    });
  }
  function post(url, body) {
    return fetch(url, {method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": CSRF},
      body: JSON.stringify(body || {})})
      .then(function (r) { return r.json().then(function (j) { return {ok: r.ok, body: j}; }); });
  }
  function get(url) {
    return fetch(url, {credentials: "same-origin"}).then(function (r) {
      if (r.status === 401) { window.location = "/login"; throw new Error("signed out"); }
      return r.json();
    });
  }
  function num(v, nd, unit) {
    return (v === null || v === undefined) ? "-" : Number(v).toFixed(nd) + (unit || "");
  }

  // ----------------------------------------------------------------- audio fx
  var audioCtx = null;
  var audioEnabled = localStorage.getItem("ane_audio_fx") !== "false";

  function initAudio() {
    if (!audioCtx) {
      try {
        var AudioContext = window.AudioContext || window.webkitAudioContext;
        if (AudioContext) audioCtx = new AudioContext();
      } catch (e) {}
    }
    if (audioCtx && audioCtx.state === "suspended") {
      audioCtx.resume();
    }
  }

  function playRelayClick() {
    if (!audioEnabled) return;
    initAudio();
    if (!audioCtx) return;
    try {
      var now = audioCtx.currentTime;
      var osc = audioCtx.createOscillator();
      var gain = audioCtx.createGain();
      osc.type = "sine";
      osc.frequency.setValueAtTime(140, now);
      osc.frequency.exponentialRampToValueAtTime(30, now + 0.04);
      gain.gain.setValueAtTime(0.4, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.04);
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.start(now);
      osc.stop(now + 0.04);

      var osc2 = audioCtx.createOscillator();
      var gain2 = audioCtx.createGain();
      osc2.type = "triangle";
      osc2.frequency.setValueAtTime(1200, now + 0.01);
      osc2.frequency.exponentialRampToValueAtTime(200, now + 0.035);
      gain2.gain.setValueAtTime(0.2, now + 0.01);
      gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.035);
      osc2.connect(gain2);
      gain2.connect(audioCtx.destination);
      osc2.start(now + 0.01);
      osc2.stop(now + 0.035);
    } catch (e) {}
  }

  function playKeyClick() {
    if (!audioEnabled) return;
    initAudio();
    if (!audioCtx) return;
    try {
      var now = audioCtx.currentTime;
      var osc = audioCtx.createOscillator();
      var gain = audioCtx.createGain();
      osc.type = "triangle";
      osc.frequency.setValueAtTime(800, now);
      osc.frequency.exponentialRampToValueAtTime(80, now + 0.025);
      gain.gain.setValueAtTime(0.25, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.025);
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.start(now);
      osc.stop(now + 0.025);
    } catch (e) {}
  }

  function playAlertAlarm() {
    if (!audioEnabled) return;
    initAudio();
    if (!audioCtx) return;
    try {
      var now = audioCtx.currentTime;
      [0, 0.12].forEach(function (offset) {
        var osc = audioCtx.createOscillator();
        var gain = audioCtx.createGain();
        osc.type = "sawtooth";
        osc.frequency.setValueAtTime(880, now + offset);
        osc.frequency.setValueAtTime(660, now + offset + 0.04);
        gain.gain.setValueAtTime(0.12, now + offset);
        gain.gain.exponentialRampToValueAtTime(0.001, now + offset + 0.08);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start(now + offset);
        osc.stop(now + offset + 0.08);
      });
    } catch (e) {}
  }

  function playSuccessChime() {
    if (!audioEnabled) return;
    initAudio();
    if (!audioCtx) return;
    try {
      var now = audioCtx.currentTime;
      [523.25, 659.25, 783.99].forEach(function (freq, i) {
        var osc = audioCtx.createOscillator();
        var gain = audioCtx.createGain();
        osc.type = "sine";
        osc.frequency.setValueAtTime(freq, now + i * 0.07);
        gain.gain.setValueAtTime(0.15, now + i * 0.07);
        gain.gain.exponentialRampToValueAtTime(0.001, now + i * 0.07 + 0.25);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start(now + i * 0.07);
        osc.stop(now + i * 0.07 + 0.25);
      });
    } catch (e) {}
  }

  var audioBtn = $("audio-toggle");
  if (audioBtn) {
    audioBtn.classList.toggle("active", audioEnabled);
    audioBtn.addEventListener("click", function () {
      audioEnabled = !audioEnabled;
      localStorage.setItem("ane_audio_fx", audioEnabled ? "true" : "false");
      audioBtn.classList.toggle("active", audioEnabled);
      if (audioEnabled) {
        initAudio();
        playKeyClick();
      }
    });
  }

  // ------------------------------------------------------------------ charts
  function makeChart(id, color, unit) {
    var isPps = id === "c-pps";
    var strokeColor = isPps ? AMBER : BLUE;
    var fillColor = isPps ? "rgba(245, 158, 11, 0.08)" : "rgba(0, 229, 255, 0.08)";
    return new Chart($(id), {
      type: "line",
      data: {labels: [], datasets: [{data: [], borderColor: strokeColor, borderWidth: 2.5, tension: 0.25,
        pointRadius: [], pointBackgroundColor: [], fill: true, backgroundColor: fillColor}]},
      options: {animation: false, maintainAspectRatio: false, responsive: true,
        interaction: {mode: "index", intersect: false},
        plugins: {legend: {display: false},
          tooltip: {callbacks: {label: function (c) { return c.parsed.y + " " + unit; }}}},
        scales: {
          x: {ticks: {maxTicksLimit: 6, color: "#64748b", font: {family: "'JetBrains Mono', monospace", size: 10}}, grid: {display: false}},
          y: {beginAtZero: true, ticks: {color: "#94a3b8", font: {family: "'JetBrains Mono', monospace", size: 10}}, grid: {color: "rgba(255, 255, 255, 0.06)"}}}}
    });
  }
  var cLat = makeChart("c-latency", BLUE, "ms"), cPps = makeChart("c-pps", AMBER, "pkt/s");
  function setChart(ch, rows, key) {
    var ds = ch.data.datasets[0];
    ch.data.labels = rows.map(function (r) {
      return new Date(r.epoch * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"});
    });
    ds.data = rows.map(function (r) { return r[key]; });
    ds.pointRadius = rows.map(function (r) { return r.abnormal ? 4 : 0; });
    ds.pointBackgroundColor = rows.map(function () { return ORANGE; });
    ch.update("none");
  }

  // ------------------------------------------------------------------- pulse
  function drawPulse(rows) {
    var bar = $("pulse");
    bar.replaceChildren();
    rows.slice(-90).forEach(function (r) {
      var t = document.createElement("i");
      t.className = r.abnormal ? "flag" : (r.fault ? "fault" : "ok");
      t.title = new Date(r.epoch * 1000).toLocaleTimeString() + ": " +
        (LABELS[r.label] || r.label) + (r.abnormal ? " (flagged)" : "");
      bar.appendChild(t);
    });
  }

  // ------------------------------------------------------------------ status
  var curMode = null, pending = null, latestNet = null;
  var faultStartTime = null, prevStatus = null, prevIncidentStatus = null;
  var activeIntensity = "med", activeDuration = "30";

  function showStatus(st) {
    var state = st.state || "offline";
    $("state").dataset.state = state;
    var text = STATES[state] || state;
    if (st.dry_run && state !== "offline") text += " (dry run)";
    if (st.fault) text += ". Fault running: " + (LABELS[st.fault] || st.fault.replace("_", " "));
    $("state-text").textContent = text;
    var last = st.last || {};
    $("v-label").textContent = last.label ? (LABELS[last.label] || last.label) : "-";
    $("v-latency").textContent = num(last.latency_ms, 1, " ms");
    $("v-loss").textContent = num(last.loss_pct, 0, "%");
    $("v-thr").textContent = num(last.throughput_mbps, 3, " Mbps");
    $("v-pps").textContent = num(last.pps, 0);
    $("v-syn").textContent = num(last.syn_ratio, 2);
    $("v-path").textContent = state === "offline" ? "-" : (st.on_backup ? "Backup path (via r3)" : "Primary path");
    $("v-blocked").textContent = (st.blocked && st.blocked.length) ? st.blocked.join(", ") : "None";
    
    var mode = (st.control && st.control.mode) || st.mode;
    if (mode && mode !== curMode) setMode(mode);
    var req = st.control && st.control.inject;
    var busy = !!st.fault || !!(req && !req.taken && (Date.now() / 1000 - req.requested) < 30);
    document.querySelectorAll("#faults button[data-fault]").forEach(function (b) {
      b.disabled = busy || state === "offline";
    });
    $("stop-fault").disabled = !st.fault;
    if (busy && st.fault) $("fault-msg").textContent = "One fault at a time. End this one to start another.";

    // Active Fault Tally Lamp & Elapsed Chronometer
    var tallyLed = $("fault-tally-led");
    var tallyTxt = $("fault-tally-text");
    if (st.fault) {
      if (faultStartTime === null) {
        faultStartTime = Date.now();
        playAlertAlarm();
      }
      var elapsed = Math.round((Date.now() - faultStartTime) / 1000);
      if (tallyLed) tallyLed.classList.add("active");
      if (tallyTxt) tallyTxt.textContent = (LABELS[st.fault] || st.fault).toUpperCase() + " [" + elapsed + "S]";
      
      // Auto-stop check
      if (activeDuration !== "cont") {
        var maxSec = parseInt(activeDuration, 10);
        if (elapsed >= maxSec && !st.stop_requested) {
          post("/api/stop-fault");
          st.stop_requested = true;
        }
      }
    } else {
      faultStartTime = null;
      if (tallyLed) tallyLed.classList.remove("active");
      if (tallyTxt) tallyTxt.textContent = "IDLE / STANDBY";
    }

    latestNet = st.net;
    renderNet(st);

    // Approval Request Handling
    var hadPending = !!pending;
    pending = st.pending_approval || null;
    $("approval").hidden = !pending;
    if (pending) {
      if (!hadPending) playAlertAlarm();
      $("approval-what").textContent = (LABELS[pending.problem] || pending.problem) + ": " + pending.what;
      $("approval-left").textContent = "Answer within " +
        Math.max(0, Math.round(pending.expires - Date.now() / 1000)) + " seconds.";
    }

    // Refresh Inspector if open
    if (!$("device-inspector").hidden && lastInspectedIp) {
      updateInspectorSecurity(lastInspectedIp);
    }

    prevStatus = st;
  }

  function setMode(mode) {
    curMode = mode;
    document.querySelectorAll("#modes button").forEach(function (b) {
      b.setAttribute("aria-checked", b.dataset.mode === mode ? "true" : "false");
    });
    $("mode-help").textContent = MODE_HELP[mode] || "";
  }

  // ----------------------------------------------------------------- polling
  function refreshFast() { get("/api/status").then(showStatus).catch(function () {}); refreshStory(); }
  function refreshSlow() {
    get("/api/metrics?n=120").then(function (rows) {
      setChart(cLat, rows, "latency_ms"); setChart(cPps, rows, "pps"); drawPulse(rows);
    }).catch(function () {});
    get("/api/incidents").then(function (rows) {
      fill($("incidents"), rows.map(function (i) {
        return [i.epoch ? new Date(i.epoch * 1000).toLocaleString() : i.time, LABELS[i.problem] || i.problem, i.action || "-", i.status.replace("_", " "),
          i.mttd === null ? "n/a" : i.mttd + " s", i.mttr === null ? "n/a" : i.mttr + " s"];
      }), 6, "No incidents yet.");
      if (rows.length > 0 && rows[0].status === "recovered" && prevIncidentStatus !== "recovered") {
        playSuccessChime();
      }
      if (rows.length > 0) prevIncidentStatus = rows[0].status;
    }).catch(function () {});
    get("/api/audit?n=25").then(function (rows) {
      fill($("audit"), rows.map(function (r) {
        return [r.epoch ? new Date(r.epoch * 1000).toLocaleTimeString() : (r.time || "").slice(11, 19), EVENTS[r.event] || r.event,
          String(r.what || r.detail || r.problem || r.scenario || "")];
      }), 3, "Nothing logged yet.");
    }).catch(function () {});
  }

  // ------------------------------------------------ live network (real state)
  var HOSTS = {"10.0.1.11": "h1", "10.0.1.12": "h2", "10.0.1.13": "h3", "10.0.1.14": "h4",
    "10.0.2.11": "h5", "10.0.2.12": "h6", "10.0.2.100": "the web server"};
  var FAULT_NAMES = {link_failure: "link failure", syn_flood: "SYN flood", port_scan: "port scan",
    latency_spike: "latency spike", congestion: "congestion"};
  var prevSig = {}, showChecks = false;
  function name(ip) { return HOSTS[ip] || ip; }
  function show(id, on) { var el = $(id); if (el) el.classList.toggle("off", !on); }
  function pulse(id) {
    var el = $(id); if (!el) return;
    el.classList.remove("pulse"); void el.getBoundingClientRect();
    el.classList.add("pulse"); setTimeout(function () { el.classList.remove("pulse"); }, 3200);
  }
  function dropText(drops) {
    return drops.map(function (d) {
      return "DROP " + name(d.src) + (d.packets === null ? "" : ": " + d.packets.toLocaleString() + " pkts");
    }).join(", ");
  }

  function renderNet(st) {
    var net = st.net, offline = st.state === "offline", fault = st.fault;
    var req = st.control && st.control.inject;
    var starting = !!(req && !req.taken && (Date.now() / 1000 - req.requested) < 30);
    if (!net) {
      $("live-caption").textContent = offline
        ? "The monitor is not running, so there is nothing live to show. Start run_monitor.py."
        : "Waiting for the first measurement from the monitor.";
      return;
    }
    var r1 = net.routers.r1, r2 = net.routers.r2, path = net.path;
    var down = net.primary.up === false;
    var delay = net.primary.delay_ms;
    var slow = !down && ((delay !== null && delay > 20) || fault === "latency_spike");
    var attacker = fault === "syn_flood" || fault === "port_scan";
    var blocked = r1.drops.some(function (d) { return d.src === "10.0.1.14"; });
    var lost = down && path !== "backup";

    $("n-h4").classList.toggle("hot", attacker && !blocked);
    var qBadge = $("h4-quarantined-badge");
    if (qBadge) qBadge.classList.toggle("off", !blocked);

    // links
    var lp = $("link-primary");
    lp.classList.toggle("down", down); lp.classList.toggle("slow", slow);
    show("x-primary", down);
    show("t-delay", slow);
    $("t-delay").textContent = delay !== null && delay > 20 ? "delay " + Math.round(delay) + " ms" : "slow link";
    $("link-b1").classList.toggle("slow", path === "backup");
    $("link-b2").classList.toggle("slow", path === "backup");
    $("link-b1").style.stroke = $("link-b2").style.stroke = path === "backup" ? "#00e5ff" : "";

    // moving traffic flows
    show("f-main-lost", lost);
    show("f-main-primary", !lost && path !== "backup");
    show("f-main-backup", !lost && path === "backup");
    show("f-attack-r1", attacker && !offline);
    show("f-attack-primary", attacker && !blocked && !lost && path !== "backup");
    show("f-attack-backup", attacker && !blocked && path === "backup");
    var heavy = fault === "congestion";
    show("f-heavy-primary", heavy && path !== "backup" && !lost);
    show("f-heavy-backup", heavy && path === "backup");

    // router labels and drop badges
    $("t-r1path").textContent = r1.path ? "route to LAN2: " + r1.path : "";
    $("t-r2path").textContent = r2.path ? "route to LAN1: " + r2.path : "";
    ["r1", "r2"].forEach(function (r) {
      var d = net.routers[r].drops;
      show("b-" + r, d.length > 0);
      $("t-b-" + r).textContent = dropText(d).slice(0, 26);
    });

    // flash whatever just changed on a router
    var sig = {"n-r1": r1.via + "|" + dropText(r1.drops.map(function (d) { return {src: d.src, packets: null}; })),
      "n-r2": r2.via + "|" + dropText(r2.drops.map(function (d) { return {src: d.src, packets: null}; }))};
    Object.keys(sig).forEach(function (id) {
      if (prevSig[id] !== undefined && prevSig[id] !== sig[id]) pulse(id);
      prevSig[id] = sig[id];
    });

    // one plain diagnostic sentence
    var text;
    if (offline) text = "The monitor is not running, so this is the last state it reported.";
    else if (starting) text = "Starting the fault in the simulated network...";
    else if (down && path === "backup") text = "The link r1 to r2 is down. r1 and r2 changed their routing tables to go through r3, so traffic flows again.";
    else if (down) text = "The link r1 to r2 is down and no route has changed yet, so traffic from h1 is lost at r1.";
    else if (slow && path === "backup") text = "The r1 to r2 link is slow. Both routers now send traffic through r3.";
    else if (slow) text = "The r1 to r2 link is slow, so every web request waits longer.";
    else if (attacker && blocked) text = "r1 now drops every packet from h4 (" + (r1.drops[0].packets === null ? "blocked" : r1.drops[0].packets.toLocaleString() + " dropped so far") + "). The server no longer receives the attack.";
    else if (attacker) text = "h4 is attacking the web server (" + FAULT_NAMES[fault] + "). Nothing blocks it yet.";
    else if (heavy) text = "A heavy flow from h2 is filling the 10 Mbit link.";
    else if (blocked) text = "r1 is blocking " + name(r1.drops[0].src) + ". The block expires by itself after 10 minutes.";
    else if (path === "backup") text = "Traffic is using the backup path through r3. It returns to the primary path by itself once r1 to r2 is healthy.";
    else text = "Normal: traffic from h1 reaches the web server over the primary path.";
    $("live-caption").textContent = text;

    renderRouterState(net);
  }

  function row(dd, cls) { var e = document.createElement("dd"); e.textContent = dd; if (cls) e.className = cls; return e; }
  var prevRows = {};
  function renderRouterState(net) {
    var box = $("rstate"), groups = [];
    ["r1", "r2"].forEach(function (r) {
      var x = net.routers[r];
      groups.push({id: r, title: r + " (router)", lines: [
        ["Route to " + x.route + ": " + (x.via ? "via " + x.via + " (" + x.path + " path)" : "none"), x.path === "backup" ? "bad" : ""],
        [x.drops.length ? x.drops.map(function (d) {
          return "firewall DROP from " + d.src + " (" + name(d.src) + ")" + (d.packets === null ? "" : ", " + d.packets.toLocaleString() + " packets dropped");
        }).join("\n") : "firewall: no DROP rules", x.drops.length ? "bad" : "good"]]});
    });
    var p = net.primary;
    groups.push({id: "link", title: "Link r1 to r2", lines: [
      ["state: " + (p.up === null ? "unknown" : p.up ? "UP" : "DOWN"), p.up === false ? "bad" : "good"],
      ["configured delay: " + (p.delay_ms === null ? "none (default)" : Math.round(p.delay_ms) + " ms"), p.delay_ms > 20 ? "bad" : ""]]});
    box.replaceChildren();
    groups.forEach(function (g) {
      var sig = JSON.stringify(g.lines.map(function (l) { return l[0].replace(/, \d[\d,]* packets dropped/g, ""); }));
      var div = document.createElement("div"); div.className = "grp";
      if (prevRows[g.id] !== undefined && prevRows[g.id] !== sig) div.classList.add("changed");
      prevRows[g.id] = sig;
      var dt = document.createElement("dt"); dt.textContent = g.title; div.appendChild(dt);
      g.lines.forEach(function (l) {
        var dd = row(l[0], l[1]); dd.style.whiteSpace = "pre-line"; div.appendChild(dd);
      });
      box.appendChild(div);
    });
  }

  function renderSteps(t) {
    var ol = $("steps");
    ol.replaceChildren();
    if (!t || !t.fault) {
      var li = document.createElement("li"); li.className = "muted";
      li.textContent = 'No fault yet. Pick one under "Try a fault".'; ol.appendChild(li); return;
    }
    var running = t.active, marked = false;
    t.steps.forEach(function (s) {
      var li = document.createElement("li");
      if (s.done) {
        li.className = "done";
        if (s.key === "verify" && t.outcome && t.outcome !== "resolved") li.className = t.outcome === "advice only" || t.outcome === "watch only" ? "warn" : "bad";
      } else if (running && !marked) { li.className = "run"; marked = true; }
      var tm = document.createElement("span"); tm.className = "tm";
      tm.textContent = s.t === null || s.t === undefined ? "" : "+" + s.t.toFixed(1) + " s";
      var st = document.createElement("span"); st.className = "st"; st.textContent = s.label;
      li.appendChild(tm); li.appendChild(st);
      if (s.detail) { var dt = document.createElement("span"); dt.className = "dt"; dt.textContent = s.detail; li.appendChild(dt); }
      ol.appendChild(li);
    });
  }

  function renderCommands(rows) {
    var ul = $("cmds");
    ul.replaceChildren();
    if (!rows.length) { var e = document.createElement("li"); e.className = "muted"; e.textContent = "Nothing yet."; ul.appendChild(e); return; }
    rows.forEach(function (r) {
      var li = document.createElement("li"); if (r.kind === "check") li.className = "check";
      var w = document.createElement("span"); w.className = "when"; w.textContent = new Date(r.epoch * 1000).toLocaleTimeString();
      var n = document.createElement("span"); n.className = "node"; n.textContent = r.node;
      var c = document.createElement("code"); c.textContent = r.cmd;
      var res = document.createElement("span"); res.className = "res " + (r.rc === 0 ? "ok" : "fail");
      res.textContent = r.dry_run ? "dry run" : (r.rc === 0 ? "ok" : "failed");
      li.appendChild(w); li.appendChild(n); li.appendChild(c); li.appendChild(res);
      if (r.out && (r.rc !== 0 || r.kind === "check")) { var o = document.createElement("span"); o.className = "out"; o.textContent = r.out.split("\n")[0].slice(0, 120); li.appendChild(o); }
      ul.appendChild(li);
    });
  }
  function refreshStory() {
    get("/api/timeline").then(renderSteps).catch(function () {});
    get("/api/commands?n=20" + (showChecks ? "" : "&changes=1")).then(renderCommands).catch(function () {});
  }
  $("show-checks").addEventListener("change", function (e) { showChecks = e.target.checked; refreshStory(); });

  // ------------------------------------------------ interactive topology & inspector
  var lastInspectedIp = "10.0.1.14";

  function inspectNode(el) {
    if (!el) return;
    playKeyClick();
    var node = el.dataset.node || "";
    var ip = el.dataset.ip || "";
    if (ip === "web-server" || node === "web") {
      ip = "10.0.2.100";
    }
    var role = el.dataset.role || "";
    var gw = el.dataset.gw || "";
    var subnet = el.dataset.subnet || "";
    lastInspectedIp = ip;

    document.querySelectorAll(".topo-node").forEach(function (n) { n.classList.remove("selected"); });
    el.classList.add("selected");

    $("insp-title").textContent = "DEVICE: " + (node.toUpperCase()) + " (" + ip + ")";
    $("insp-ip").textContent = ip + (node.startsWith("h") ? " / eth0" : "");
    $("insp-gw").textContent = gw;
    $("insp-subnet").textContent = subnet;
    var lastOctet = parseInt(ip.split(".").pop(), 10) || 1;
    $("insp-mac").textContent = "00:00:0a:00:01:" + (lastOctet < 16 ? "0" : "") + lastOctet.toString(16);
    $("insp-role").textContent = role;
    
    updateInspectorSecurity(ip);
    $("device-inspector").hidden = false;
    $("insp-terminal-output").textContent = "Loaded telemetry for " + node.toUpperCase() + " [" + ip + "]. Diagnostic ping and firewall controls active.";
  }

  function updateInspectorSecurity(ip) {
    if (!latestNet) return;
    var r1Drops = (latestNet.routers && latestNet.routers.r1 && latestNet.routers.r1.drops) || [];
    var isDropped = r1Drops.some(function (d) { return d.src === ip; });
    var secEl = $("insp-firewall");
    var qBtn = $("insp-quarantine-btn");
    var rBtn = $("insp-release-btn");
    if (isDropped) {
      secEl.textContent = "QUARANTINED (DROP filter active)";
      secEl.className = "vfd-txt red blink";
      if (qBtn) qBtn.disabled = true;
      if (rBtn) rBtn.disabled = false;
    } else {
      secEl.textContent = "UNRESTRICTED (traffic flowing)";
      secEl.className = "vfd-txt green";
      if (qBtn) qBtn.disabled = false;
      if (rBtn) rBtn.disabled = true;
    }
  }

  document.querySelectorAll(".topo-node").forEach(function (el) {
    el.style.cursor = "pointer";
    el.addEventListener("click", function () { inspectNode(el); });
  });

  $("insp-close-btn").addEventListener("click", function () {
    playKeyClick();
    $("device-inspector").hidden = true;
    document.querySelectorAll(".topo-node").forEach(function (n) { n.classList.remove("selected"); });
  });

  $("insp-ping-btn").addEventListener("click", function () {
    playKeyClick();
    $("insp-terminal-output").textContent = "PING " + lastInspectedIp + " (56 data bytes)...";
    post("/api/manual/ping", {target: lastInspectedIp}).then(function (r) {
      if (r.ok && r.body.ok) {
        $("insp-terminal-output").textContent = "64 bytes from " + r.body.target + ": icmp_seq=1 ttl=64 time=" + r.body.rtt_ms + " ms [OK]";
      } else {
        var loss = r.body ? r.body.status : "Request timed out";
        $("insp-terminal-output").textContent = "PING FAILED: " + loss;
      }
    });
  });

  $("insp-quarantine-btn").addEventListener("click", function () {
    playKeyClick();
    $("insp-terminal-output").textContent = "Sending quarantine order for " + lastInspectedIp + "...";
    post("/api/manual/quarantine", {ip: lastInspectedIp}).then(function (r) {
      if (r.ok) {
        $("insp-terminal-output").textContent = "Quarantine applied: iptables -I FORWARD -s " + lastInspectedIp + " -j DROP active.";
        refreshFast();
      }
    });
  });

  $("insp-release-btn").addEventListener("click", function () {
    playKeyClick();
    $("insp-terminal-output").textContent = "Sending release order for " + lastInspectedIp + "...";
    post("/api/manual/release", {ip: lastInspectedIp}).then(function (r) {
      if (r.ok) {
        $("insp-terminal-output").textContent = "Restrictions removed: iptables DROP rules cleared for " + lastInspectedIp + ".";
        refreshFast();
      }
    });
  });

  // ------------------------------------------------ fault calibrator
  document.querySelectorAll("#fault-intensity .step-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      playRelayClick();
      document.querySelectorAll("#fault-intensity .step-btn").forEach(function (b) { b.classList.remove("active"); });
      btn.classList.add("active");
      activeIntensity = btn.dataset.intensity;
    });
  });

  document.querySelectorAll("#fault-duration .step-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      playRelayClick();
      document.querySelectorAll("#fault-duration .step-btn").forEach(function (b) { b.classList.remove("active"); });
      btn.classList.add("active");
      activeDuration = btn.dataset.duration;
    });
  });

  // ---------------------------------------------------------------- controls
  document.querySelectorAll("#modes button").forEach(function (b) {
    b.addEventListener("click", function () {
      playRelayClick();
      var m = b.dataset.mode; setMode(m);
      post("/api/mode", {mode: m}).then(function (r) { if (!r.ok) $("mode-help").textContent = r.body.error; });
    });
  });
  document.querySelectorAll("#faults button[data-fault]").forEach(function (b) {
    b.addEventListener("click", function () {
      playKeyClick();
      post("/api/inject", {scenario: b.dataset.fault}).then(function (r) {
        $("fault-msg").textContent = r.ok ? "Requested. It starts within a few seconds." : r.body.error;
      });
    });
  });
  $("stop-fault").addEventListener("click", function () {
    playKeyClick();
    post("/api/stop-fault").then(function () { $("fault-msg").textContent = "Ending the fault."; });
  });
  function answer(ok) {
    if (!pending) return;
    playKeyClick();
    post("/api/approval", {id: pending.id, approved: ok}).then(function (r) {
      if (!r.ok) $("approval-left").textContent = r.body.error;
      $("approval").hidden = true; refreshFast();
    });
  }
  $("approve").addEventListener("click", function () { answer(true); });
  $("decline").addEventListener("click", function () { answer(false); });

  refreshFast(); refreshSlow();
  setInterval(refreshFast, 2000);
  setInterval(refreshSlow, 4000);
})();
