/* NetMon dashboard */
(() => {
  "use strict";

  // ------------------------------------------------------------------ state
  const S = {
    devices: new Map(),       // name -> device
    links: [],
    alarms: new Map(),        // id -> active alarm
    events: [],
    panels: [],
    thresholds: {},
    demo: false,
    me: { username: "", role: "admin", auth_enabled: false },
    view: "overview",
    openDev: null,            // switch name, or "panel:<name>"
    selPort: null,
    portFilter: "all",
    chartRange: "day",
  };
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const store = {
    get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : v; } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
  };
  const isAdmin = () => S.me.role === "admin";

  async function api(path, opts = {}) {
    const o = { ...opts, headers: { ...(opts.headers || {}) } };
    if (o.method && o.method !== "GET") o.headers["X-Requested-With"] = "netmon";
    const r = await fetch(path, o);
    if (r.status === 401) { location.href = "/login"; throw new Error("login required"); }
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
    return r.json();
  }

  // ------------------------------------------------------------------ formatters
  const fmtBps = (b) => {
    if (!b) return "0";
    const u = ["bps", "Kbps", "Mbps", "Gbps"]; let i = 0;
    while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; }
    return `${b < 10 ? b.toFixed(1) : Math.round(b)} ${u[i]}`;
  };
  const fmtSpeed = (m) => !m ? "—" : m >= 1000 ? `${m / 1000}G` : `${m}M`;
  const fmtTime = (ts) => {
    if (!ts) return "—";
    const d = new Date(ts * 1000), now = new Date();
    const t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
    return d.toDateString() === now.toDateString() ? t : `${d.toLocaleDateString([], { month: "short", day: "numeric" })} ${t.slice(0, 5)}`;
  };
  const fmtDur = (sec) => {
    sec = Math.max(0, Math.floor(sec));
    const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
    if (d) return `${d}d ${h}h`;
    if (h) return `${h}h ${m}m`;
    if (m) return `${m}m ${String(s).padStart(2, "0")}s`;
    return `${s}s`;
  };
  const ago = (ts) => ts ? `${fmtDur(Date.now() / 1000 - ts)} ago` : "—";
  const model = (d) => { const m = (d.sysdescr || "").match(/\(([^)]+)\)/); return m ? m[1] : ""; };
  const patchText = (p) => p.patch ? `${p.patch.panel}/${p.patch.panel_port}${p.patch.location ? " · " + p.patch.location : ""}` : "";

  // ------------------------------------------------------------------ helpers
  const linkPortSet = () => {
    const s = new Set();
    for (const l of S.links) { s.add(`${l.a_device}|${l.a_port}`); s.add(`${l.b_device}|${l.b_port}`); }
    return s;
  };
  const alarmKeys = () => new Set([...S.alarms.values()].filter((a) => a.severity === "critical").map((a) => a.key));
  const portClass = (dev, p, akeys) => {
    if (p.admin !== "up") return "admin";
    if (akeys.has(`${dev.name}|${p.name}`)) return "alarm";
    return p.oper === "up" ? "up" : "down";
  };
  const physical = (p) => !/^(Po|Vl|Lo|Tu|Nu)/i.test(p.name);
  const envState = { 1: "ok", 2: "warn", 3: "bad", 4: "bad", 5: "na", 6: "bad" };
  const healthSummary = (d) => {
    const h = d.health || {};
    const temps = h.temps || [];
    const maxT = temps.reduce((m, t) => Math.max(m, t.value ?? -1), -1);
    const worst = (arr) => arr.reduce((w, x) => Math.max(w, x.state === 5 ? 1 : x.state), 1);
    return {
      cpu: h.cpu, mem: h.mem_pct, temp: maxT >= 0 ? maxT : null,
      tempState: envState[worst(temps)], fanState: envState[worst(h.fans || [])], psuState: envState[worst(h.psus || [])],
      fans: (h.fans || []).length, psus: (h.psus || []).length,
      poe: d.poe,
    };
  };

  // ------------------------------------------------------------------ topology
  const COLORS = {
    up:      { background: "#0f2a1d", border: "#22c55e", highlight: { background: "#14402a", border: "#4ade80" }, hover: { background: "#14402a", border: "#4ade80" } },
    warning: { background: "#2b2210", border: "#f59e0b", highlight: { background: "#3d2f12", border: "#fbbf24" }, hover: { background: "#3d2f12", border: "#fbbf24" } },
    down:    { background: "#2d1111", border: "#ef4444", highlight: { background: "#451616", border: "#f87171" }, hover: { background: "#451616", border: "#f87171" } },
    unknown: { background: "#172033", border: "#64748b", highlight: { background: "#1e293b", border: "#94a3b8" }, hover: { background: "#1e293b", border: "#94a3b8" } },
    panel:   { background: "#141b2a", border: "#475569", highlight: { background: "#1e293b", border: "#94a3b8" }, hover: { background: "#1e293b", border: "#94a3b8" } },
  };
  const nodes = new vis.DataSet();
  const edges = new vis.DataSet();
  let floorLabels = [];
  let showPanels = store.get("netmon.panels", "0") === "1";
  $("showPanels").checked = showPanels;
  const network = new vis.Network($("topo"), { nodes, edges }, {
    physics: false,
    interaction: { hover: true, tooltipDelay: 120, zoomSpeed: 0.6 },
    nodes: {
      shape: "box", margin: { top: 8, bottom: 8, left: 12, right: 12 }, borderWidth: 2,
      shapeProperties: { borderRadius: 8 },
      font: { color: "#e6edf6", face: "Segoe UI, system-ui, sans-serif", size: 13, multi: "html", bold: { size: 14, color: "#ffffff" } },
    },
    edges: { smooth: { type: "cubicBezier", forceDirection: "vertical", roundness: 0.45 }, selectionWidth: 1, hoverWidth: 1 },
  });

  function layoutPositions(devs) {
    const pos = {};
    floorLabels = [];
    const cores = devs.filter((d) => d.role === "core").sort((a, b) => a.name.localeCompare(b.name));
    const dists = devs.filter((d) => d.role === "distribution").sort((a, b) => a.name.localeCompare(b.name));
    const acc = devs.filter((d) => d.role !== "core" && d.role !== "distribution");
    const row = (list, y, gap) => list.forEach((d, i) => { pos[d.name] = { x: (i - (list.length - 1) / 2) * gap, y }; });
    row(cores, -150, 260);
    if (cores.length) floorLabels.push({ text: "CORE / SERVER ROOM", x: 0, y: -195 });
    row(dists, 0, 200);
    const yAcc = dists.length ? 150 : 110;
    const floors = [...new Set(acc.map((d) => d.floor))].sort((a, b) => a - b);
    const SW = 118, FG = 40;
    const groups = floors.map((f) => acc.filter((d) => d.floor === f).sort((a, b) => a.name.localeCompare(b.name)));
    const total = groups.reduce((t, g) => t + g.length * SW, 0) + FG * (groups.length - 1);
    let x = -total / 2 + SW / 2;
    groups.forEach((g, gi) => {
      const x0 = x;
      g.forEach((d) => { pos[d.name] = { x, y: yAcc }; x += SW; });
      floorLabels.push({ text: `FLOOR ${floors[gi]}`, x: (x0 + x - SW) / 2, y: yAcc + (showPanels ? 140 : 50) });
      x += FG;
    });
    return pos;
  }

  function devTitle(d) {
    const alarms = [...S.alarms.values()].filter((a) => a.device === d.name).length;
    const h = healthSummary(d);
    return [
      `${d.name}  (${d.host})`,
      model(d) && `Model: ${model(d)}`,
      `Status: ${d.status.toUpperCase()}`,
      `Ports up: ${d.ports_up}/${d.ports_total}`,
      h.cpu != null && `CPU ${Math.round(h.cpu)}%  ·  Temp ${h.temp ?? "—"}°C`,
      alarms && `Active alarms: ${alarms}`,
      d.uptime && `Uptime: ${fmtDur(d.uptime)}`,
      "Click for port details",
    ].filter(Boolean).join("\n");
  }

  let needFit = true;
  function renderTopology() {
    const devs = [...S.devices.values()];
    const pos = layoutPositions(devs);
    const existing = new Set(nodes.getIds());
    const upd = devs.map((d) => {
      const n = { id: d.name, label: `<b>${d.name}</b>\n${d.host}`, color: COLORS[d.status] || COLORS.unknown,
        title: devTitle(d), borderWidth: d.status === "down" ? 3 : 2, shape: "box", font: {} };
      if (!existing.has(d.name)) Object.assign(n, pos[d.name]);
      return n;
    });
    // patch panels sit under the switch(es) they serve
    const pUpd = [], pEdges = [];
    if (showPanels) {
      for (const p of S.panels) {
        const sws = p.switches.filter((s) => pos[s]);
        if (!sws.length) continue;
        const id = `panel:${p.name}`;
        const core = sws.every((s) => S.devices.get(s) && S.devices.get(s).role === "core");
        const x = sws.reduce((t, s) => t + pos[s].x, 0) / sws.length - (core ? 150 : 0), y = core ? Math.min(...sws.map((s) => pos[s].y)) : Math.max(...sws.map((s) => pos[s].y)) + 85;
        const n = { id, label: p.name, shape: "box", color: COLORS.panel, borderWidth: 1,
          font: { size: 11, color: "#94a3b8" }, margin: 6, title: `${p.name}\n${p.entries.length} cabled ports\nClick for the panel view` };
        if (!existing.has(id)) Object.assign(n, { x, y });
        pUpd.push(n);
        sws.forEach((s) => pEdges.push({ id: `pe:${p.name}:${s}`, from: s, to: id, dashes: [2, 4], width: 1,
          color: { color: "#475569", opacity: 0.8 }, smooth: false, _down: false }));
      }
    }
    nodes.update([...upd, ...pUpd]);
    const keep = new Set([...devs.map((d) => d.name), ...pUpd.map((n) => n.id)]);
    nodes.remove(nodes.getIds().filter((id) => !keep.has(id)));

    const eu = S.links.filter((l) => keep.has(l.a_device) && keep.has(l.b_device)).map((l) => {
      const down = l.status === "down", unk = l.status === "unknown";
      return {
        id: l.id, from: l.a_device, to: l.b_device,
        color: { color: down ? "#ef4444" : unk ? "#64748b" : "#22c55e", opacity: down ? 1 : 0.75, highlight: "#38bdf8", hover: "#38bdf8" },
        width: down ? 3 : l.speed >= 10000 ? 2.5 : 1.5,
        dashes: down ? [8, 6] : false,
        title: `${l.a_device} ${l.a_port}  ⇄  ${l.b_device} ${l.b_port}\nSpeed: ${fmtSpeed(l.speed)}\nStatus: ${l.status.toUpperCase()}`,
        _down: down,
      };
    });
    edges.update([...eu, ...pEdges]);
    const ekeep = new Set([...eu.map((e) => e.id), ...pEdges.map((e) => e.id)]);
    edges.remove(edges.getIds().filter((id) => !ekeep.has(id)));
    if (needFit && devs.length) { needFit = false; setTimeout(() => network.fit({ animation: false }), 50); }
  }

  network.on("afterDrawing", (ctx) => {
    ctx.save();
    ctx.font = "600 12px Segoe UI, system-ui, sans-serif";
    ctx.fillStyle = "#5c6b85";
    ctx.textAlign = "center";
    for (const f of floorLabels) ctx.fillText(f.text, f.x, f.y);
    ctx.restore();
  });
  network.on("click", (p) => { if (p.nodes.length) openDrawer(p.nodes[0]); });
  network.on("hoverNode", () => { $("topo").style.cursor = "pointer"; });
  network.on("blurNode", () => { $("topo").style.cursor = "default"; });
  let fitT = null;
  new ResizeObserver(() => { clearTimeout(fitT); fitT = setTimeout(() => network.fit({ animation: false }), 200); }).observe($("topo"));
  $("fitBtn").onclick = () => network.fit({ animation: { duration: 400 } });
  $("showPanels").onchange = (e) => {
    showPanels = e.target.checked; store.set("netmon.panels", showPanels ? "1" : "0");
    nodes.clear(); edges.clear(); needFit = true; renderTopology();
  };

  let blinkOn = false;
  setInterval(() => {
    blinkOn = !blinkOn;
    const down = edges.get({ filter: (e) => e._down });
    if (down.length) edges.update(down.map((e) => ({ id: e.id, color: { ...e.color, color: blinkOn ? "#ef4444" : "#5b1a1a" } })));
  }, 600);

  // ------------------------------------------------------------------ header
  function renderStats() {
    const devs = [...S.devices.values()];
    const up = devs.filter((d) => d.status === "up" || d.status === "warning").length;
    $("stSw").textContent = `${up}/${devs.length}`;
    const lu = S.links.filter((l) => l.status === "up").length;
    $("stLinks").textContent = `${lu}/${S.links.length}`;
    $("stLinks").style.color = lu < S.links.length ? "var(--down)" : "";
    $("stSw").style.color = up < devs.length ? "var(--down)" : "";
    let pu = 0, pt = 0;
    devs.forEach((d) => { pu += d.ports_up; pt += d.ports_total; });
    $("stPorts").textContent = `${pu}/${pt}`;
    const n = S.alarms.size;
    const crit = [...S.alarms.values()].filter((a) => a.severity === "critical").length;
    $("stAlarms").textContent = n;
    $("stAlarmBox").classList.toggle("on", crit > 0);
    $("stAlarmBox").classList.toggle("warnonly", n > 0 && crit === 0);
    $("alarmCount").textContent = n;
    $("alarmCount").classList.toggle("hot", n > 0);
    document.title = n ? `(${n}) ${crit ? "🔴" : "🟠"} NetMon` : "NetMon";
    $("demoBadge").hidden = !S.demo;
    $("demoFail").hidden = !S.demo || !isAdmin();
  }

  function applyRole() {
    document.body.classList.toggle("viewer", !isAdmin());
    $("userName").textContent = S.me.auth_enabled ? `${S.me.username} · ${S.me.role}` : (S.demo ? "demo (no login)" : "");
    $("logoutBtn").hidden = !S.me.auth_enabled;
  }
  $("logoutBtn").onclick = async () => { await api("/api/logout", { method: "POST" }).catch(() => {}); location.href = "/login"; };

  // ------------------------------------------------------------------ alarms
  const sevIcon = (a) => a.severity === "warning" ? "🟠" : a.port ? "🔴" : "⛔";
  function renderAlarms() {
    const list = [...S.alarms.values()].sort((a, b) => (a.severity === b.severity ? b.raised_ts - a.raised_ts : a.severity === "critical" ? -1 : 1));
    const el = $("alarmList");
    if (!list.length) {
      el.innerHTML = `<div class="empty"><span class="big">✅</span>No active alarms. Everything monitored is OK.</div>`;
    } else {
      el.innerHTML = list.map((a) => `
        <div class="alarm-item ${a.severity === "warning" ? "warning" : ""} ${a.acked_by ? "acked" : ""}" data-dev="${esc(a.device)}" data-port="${esc(a.port || "")}">
          <div class="row1">
            <div class="msg">${sevIcon(a)} ${esc(a.message)}</div>
            <div class="dur" data-since="${a.raised_ts}">${fmtDur(Date.now() / 1000 - a.raised_ts)}</div>
          </div>
          <div class="meta">Since ${fmtTime(a.raised_ts)}${a.acked_by ? ` · Acknowledged by <b>${esc(a.acked_by)}</b>` : ""}</div>
          ${a.acked_by || !isAdmin() ? "" : `<div style="margin-top:8px"><button class="btn small danger" data-ack="${a.id}">Acknowledge</button></div>`}
        </div>`).join("");
    }
    renderBanner();
  }
  $("alarmList").addEventListener("click", (e) => {
    const ack = e.target.closest("[data-ack]");
    if (ack) { e.stopPropagation(); doAck([+ack.dataset.ack]); return; }
    const it = e.target.closest(".alarm-item");
    if (it) openDrawer(it.dataset.dev, it.dataset.port || null);
  });
  async function doAck(ids) {
    for (const id of ids) await api(`/api/alarms/${id}/ack`, { method: "POST" }).catch((e) => alert(e.message));
  }
  function renderBanner() {
    const un = [...S.alarms.values()].filter((a) => !a.acked_by && a.severity === "critical").sort((a, b) => b.raised_ts - a.raised_ts);
    $("banner").hidden = !un.length;
    if (un.length) {
      $("bannerText").textContent = `${un[0].message}${un.length > 1 ? `   ·   +${un.length - 1} more unacknowledged` : ""}`;
      $("bannerAck").textContent = un.length > 1 ? "Acknowledge all" : "Acknowledge";
      $("bannerAck").onclick = () => doAck(un.map((a) => a.id));
    }
  }
  setInterval(() => {
    document.querySelectorAll(".dur[data-since]").forEach((el) => { el.textContent = fmtDur(Date.now() / 1000 - +el.dataset.since); });
  }, 1000);

  // ------------------------------------------------------------------ sound
  let audio = null;
  let soundOn = store.get("netmon.sound", "0") === "1";
  const soundBtn = $("soundBtn");
  const paintSound = () => { soundBtn.textContent = soundOn ? "🔔 Sound on" : "🔇 Sound off"; };
  paintSound();
  soundBtn.onclick = () => { soundOn = !soundOn; store.set("netmon.sound", soundOn ? "1" : "0"); paintSound(); if (soundOn) { ensureAudio(); beep(); } };
  function ensureAudio() {
    if (!audio) { try { audio = new (window.AudioContext || window.webkitAudioContext)(); } catch { audio = null; } }
    if (audio && audio.state === "suspended") audio.resume();
  }
  function beep(soft = false) {
    if (!soundOn) return;
    ensureAudio();
    if (!audio) return;
    const t0 = audio.currentTime;
    const seq = soft ? [[660, 0], [660, 0.25]] : [[880, 0], [660, 0.22], [880, 0.44], [660, 0.66]];
    seq.forEach(([f, t]) => {
      const o = audio.createOscillator(), g = audio.createGain();
      o.type = soft ? "sine" : "square"; o.frequency.value = f;
      g.gain.setValueAtTime(0.0001, t0 + t);
      g.gain.exponentialRampToValueAtTime(soft ? 0.08 : 0.12, t0 + t + 0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, t0 + t + 0.2);
      o.connect(g).connect(audio.destination);
      o.start(t0 + t); o.stop(t0 + t + 0.21);
    });
  }
  document.addEventListener("click", () => { if (soundOn) ensureAudio(); }, { once: true });
  setInterval(() => { if ([...S.alarms.values()].some((a) => !a.acked_by && a.severity === "critical")) beep(); }, 20000);

  // ------------------------------------------------------------------ events
  let newEventIds = new Set();
  function renderEvents() {
    const q = $("eventFilter").value.trim().toLowerCase();
    const list = S.events.filter((e) => !q || `${e.device} ${e.port} ${e.message}`.toLowerCase().includes(q)).slice(0, 300);
    $("eventList").innerHTML = list.length ? list.map((e) => `
      <div class="ev ${e.severity} ${newEventIds.has(e.id) ? "new" : ""}">
        <div class="t">${fmtTime(e.ts)}</div>
        <div class="m"><b>${esc(e.device || "")}</b> ${esc(e.message)}</div>
      </div>`).join("") : `<div class="empty">No events.</div>`;
    newEventIds = new Set();
  }
  $("eventFilter").addEventListener("input", renderEvents);
  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === t));
    $("tab-alarms").hidden = t.dataset.tab !== "alarms";
    $("tab-events").hidden = t.dataset.tab !== "events";
  }));

  // ------------------------------------------------------------------ switch cards
  function renderFloors() {
    const q = $("swFilter").value.trim().toLowerCase();
    const akeys = alarmKeys();
    const devs = [...S.devices.values()].filter((d) => !q || `${d.name} ${d.host}`.toLowerCase().includes(q) ||
      d.ports.some((p) => `${p.name} ${p.alias} ${patchText(p)}`.toLowerCase().includes(q)));
    const groups = new Map();
    for (const d of devs) {
      const k = d.role === "core" ? "Core / Server room" : d.role === "distribution" ? "Distribution" : `Floor ${d.floor}`;
      const order = d.role === "core" ? -2 : d.role === "distribution" ? -1 : d.floor;
      if (!groups.has(k)) groups.set(k, { order, list: [] });
      groups.get(k).list.push(d);
    }
    $("floors").innerHTML = [...groups.entries()].sort((a, b) => a[1].order - b[1].order).map(([k, g]) => `
      <div class="floor">
        <div class="floor-title">${esc(k)}</div>
        <div class="sw-grid">
          ${g.list.sort((a, b) => a.name.localeCompare(b.name)).map((d) => {
            const al = [...S.alarms.values()].filter((a) => a.device === d.name).length;
            const ports = d.ports.filter(physical);
            const h = healthSummary(d);
            return `
            <div class="sw ${d.status}" data-dev="${esc(d.name)}" tabindex="0">
              <div class="sw-head"><span class="sw-name">${esc(d.name)}</span><span class="sw-ip">${esc(d.host)}</span></div>
              <div class="sw-meta">
                <span>${d.status === "down" ? "⛔ UNREACHABLE" : d.status === "unknown" ? "⏳ waiting for first poll" : `${d.ports_up}/${d.ports_total} ports up`}</span>
                ${al ? `<span style="color:var(--down)">${al} alarm${al > 1 ? "s" : ""}</span>` : ""}
                ${d.uptime ? `<span>up ${fmtDur(d.uptime)}</span>` : ""}
                ${model(d) ? `<span>${esc(model(d))}</span>` : ""}
              </div>
              ${h.cpu != null ? `<div class="sw-health">
                <span class="${h.cpu >= (S.thresholds.cpu_percent || 90) ? "hot" : ""}">CPU ${Math.round(h.cpu)}%</span>
                ${h.temp != null ? `<span class="${h.tempState !== "ok" ? "hot" : ""}">${h.temp}°C</span>` : ""}
                ${h.fanState !== "ok" ? `<span class="hot">Fan!</span>` : ""}
                ${h.psuState !== "ok" ? `<span class="hot">PSU!</span>` : ""}
                ${h.poe ? `<span class="${100 * h.poe.used_w / h.poe.budget_w >= (S.thresholds.poe_budget_percent || 90) ? "hot" : ""}">PoE ${Math.round(h.poe.used_w)}/${Math.round(h.poe.budget_w)} W</span>` : ""}
              </div>` : ""}
              <div class="mini">${ports.map((p) => `<i class="${portClass(d, p, akeys)}"></i>`).join("")}</div>
            </div>`;
          }).join("")}
        </div>
      </div>`).join("") || `<div class="empty">No switches match.</div>`;
  }
  $("swFilter").addEventListener("input", renderFloors);
  $("floors").addEventListener("click", (e) => { const c = e.target.closest(".sw"); if (c) openDrawer(c.dataset.dev); });
  $("floors").addEventListener("keydown", (e) => { const c = e.target.closest(".sw"); if (c && e.key === "Enter") openDrawer(c.dataset.dev); });

  // ------------------------------------------------------------------ drawer
  function openDrawer(name, port = null) {
    if (!name.startsWith("panel:") && !S.devices.has(name)) return;
    S.openDev = name;
    S.selPort = port;
    $("pFilter").value = "";
    $("drawer").hidden = false;
    $("chartBox").hidden = true;
    renderDrawer(true);
    if (port && !name.startsWith("panel:")) loadChart();
  }
  function closeDrawer() { S.openDev = null; $("drawer").hidden = true; }
  $("drawer").addEventListener("click", (e) => { if (e.target.closest("[data-close]")) closeDrawer(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  $("dPoll").onclick = async () => {
    if (!S.openDev || S.openDev.startsWith("panel:")) return;
    $("dPoll").textContent = "↻ Polling…";
    await api(`/api/devices/${encodeURIComponent(S.openDev)}/poll`, { method: "POST" }).catch(() => {});
    setTimeout(() => { $("dPoll").textContent = "↻ Poll now"; }, 1500);
  };
  $("pFilter").addEventListener("input", () => renderDrawer());
  $("pSeg").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    S.portFilter = b.dataset.f;
    $("pSeg").querySelectorAll("button").forEach((x) => x.classList.toggle("active", x === b));
    renderDrawer();
  });

  function renderDrawer(scroll = false) {
    if (!S.openDev) return;
    if (S.openDev.startsWith("panel:")) return renderPanelDrawer();
    const d = S.devices.get(S.openDev);
    if (!d) return;
    const akeys = alarmKeys(), lp = linkPortSet();
    $("dStatus").className = `sdot ${d.status}`;
    $("dName").textContent = d.name;
    $("dSub").textContent = [d.sysname, d.sysdescr].filter(Boolean).join(" · ") || "Waiting for first poll…";
    $("dPoll").hidden = !isAdmin();
    $("pTools").hidden = false;
    const h = healthSummary(d);
    const chip = (k, v, cls = "") => `<span class="chip ${cls}"><b>${k}</b>${esc(v)}</span>`;
    const stTxt = { ok: "OK", warn: "WARNING", bad: "FAILED", na: "—" };
    $("dInfo").innerHTML = [
      chip("IP", d.host), chip("Floor", d.role === "core" ? "Core" : d.floor),
      chip("Ports up", `${d.ports_up}/${d.ports_total}`), chip("Uptime", d.uptime ? fmtDur(d.uptime) : "—"),
      h.cpu != null ? chip("CPU", `${Math.round(h.cpu)}%`, h.cpu >= (S.thresholds.cpu_percent || 90) ? "err" : "") : "",
      h.mem != null ? chip("Memory", `${Math.round(h.mem)}%`, h.mem >= (S.thresholds.memory_percent || 90) ? "err" : "") : "",
      h.temp != null ? chip("Temp", `${h.temp}°C ${h.tempState !== "ok" ? stTxt[h.tempState] : ""}`, h.tempState !== "ok" ? "err" : "") : "",
      h.fans ? chip("Fans", stTxt[h.fanState], h.fanState !== "ok" ? "err" : "") : "",
      h.psus ? chip("Power", stTxt[h.psuState], h.psuState !== "ok" ? "err" : "") : "",
      h.poe ? chip("PoE", `${Math.round(h.poe.used_w)} / ${Math.round(h.poe.budget_w)} W`, 100 * h.poe.used_w / h.poe.budget_w >= (S.thresholds.poe_budget_percent || 90) ? "err" : "") : "",
      d.info && d.info.location ? chip("Location", d.info.location) : "",
      chip("Last poll", ago(d.last_poll)),
      d.last_error ? chip("Error", d.last_error, "err") : "",
    ].join("");

    const groups = new Map();
    for (const p of d.ports.filter(physical)) {
      const m = p.name.match(/^(.*?)(\d+)$/);
      const k = m ? m[1] : p.name;
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push({ p, n: m ? m[2] : "" });
    }
    $("dFace").innerHTML = [...groups.entries()].map(([k, list]) => {
      const sfp = /^(Te|Twe|Fo|Hu|Tw)/.test(k);
      return `<span class="fp-label">${esc(k)}</span><div class="fp-group ${list.length <= 4 ? "single" : ""}">${list.map(({ p, n }) =>
        `<div class="fp ${portClass(d, p, akeys)} ${sfp ? "sfp" : ""} ${p.poe_w ? "poe" : ""} ${S.selPort === p.name ? "sel" : ""}" data-port="${esc(p.name)}">${n}</div>`).join("")}</div>`;
    }).join("");

    $("pHead").innerHTML = `<tr><th>Port</th><th>Description</th><th>Status</th><th>VLAN</th><th>Speed</th>
      <th class="num">In</th><th class="num">Out</th><th class="num">Util</th><th class="num">PoE</th><th class="num">Errors</th>
      <th>Patch / location</th><th>Neighbor (CDP)</th><th>Last change</th></tr>`;
    const q = $("pFilter").value.trim().toLowerCase();
    const rows = d.ports.filter((p) => {
      if (q && !`${p.name} ${p.descr} ${p.alias} ${p.vlan ?? ""} ${p.neighbor ? p.neighbor.device : ""} ${patchText(p)}`.toLowerCase().includes(q)) return false;
      const c = portClass(d, p, akeys);
      switch (S.portFilter) {
        case "up": return c === "up";
        case "down": return c === "down" || c === "alarm";
        case "admin": return c === "admin";
        case "uplink": return lp.has(`${d.name}|${p.name}`) || !!p.neighbor;
        default: return true;
      }
    });
    $("pBody").innerHTML = rows.map((p) => {
      const c = portClass(d, p, akeys);
      const pill = { up: "Up", down: "Down", alarm: "DOWN · ALARM", admin: "Shutdown" }[c];
      const warn = S.alarms.size && [...S.alarms.values()].some((a) => a.key.startsWith(`${d.name}|${p.name}|`));
      const hot = p.util != null && p.util >= (S.thresholds.utilization_percent || 80);
      return `<tr class="${c === "alarm" ? "alarm" : warn ? "warnrow" : ""} ${S.selPort === p.name ? "sel" : ""}" data-port="${esc(p.name)}">
        <td class="mono"><b>${esc(p.name)}</b>${lp.has(`${d.name}|${p.name}`) ? `<span class="tag">UPLINK</span>` : ""}</td>
        <td class="desc">${p.alias ? esc(p.alias) : `<span class="muted">—</span>`}</td>
        <td><span class="pill ${c}">${pill}</span></td>
        <td class="mono">${p.trunk ? "trunk" : p.vlan ?? "—"}</td>
        <td class="mono">${p.oper === "up" ? fmtSpeed(p.speed) : "—"}</td>
        <td class="num">${p.oper === "up" ? fmtBps(p.in_bps) : "—"}</td>
        <td class="num">${p.oper === "up" ? fmtBps(p.out_bps) : "—"}</td>
        <td class="num ${hot ? "err-n" : ""}">${p.util != null ? p.util.toFixed(p.util < 10 ? 1 : 0) + "%" : "—"}</td>
        <td class="num">${p.poe_w ? p.poe_w.toFixed(1) + " W" : "—"}</td>
        <td class="num ${p.in_errors + p.out_errors ? "err-n" : "muted"}">${p.in_errors + p.out_errors}</td>
        <td>${p.patch ? `${esc(p.patch.panel)}/${p.patch.panel_port}<span class="muted"> ${esc(p.patch.location || "")}</span>` : `<span class="muted">—</span>`}</td>
        <td>${p.neighbor ? `${esc(p.neighbor.device.split(".")[0])} <span class="muted mono">${esc(p.neighbor.port)}</span>` : `<span class="muted">—</span>`}</td>
        <td class="muted">${p.last_change ? ago(p.last_change) : "—"}</td>
      </tr>`;
    }).join("") || `<tr><td colspan="13" class="empty">No ports match.</td></tr>`;
    if (scroll && S.selPort) {
      const tr = $("pBody").querySelector(`tr[data-port="${CSS.escape(S.selPort)}"]`);
      if (tr) tr.scrollIntoView({ block: "center" });
    }
  }

  function renderPanelDrawer() {
    const name = S.openDev.slice(6);
    const pnl = S.panels.find((p) => p.name === name);
    if (!pnl) return;
    const akeys = alarmKeys();
    const swPort = (e) => { const d = S.devices.get(e.switch); return d ? [d, d.ports.find((p) => p.name === e.switch_port)] : [null, null]; };
    $("dStatus").className = "sdot up";
    $("dName").textContent = pnl.name;
    $("dSub").textContent = `Patch panel · serves ${pnl.switches.join(", ")}`;
    $("dPoll").hidden = true;
    $("pTools").hidden = true;
    $("chartBox").hidden = true;
    const used = pnl.entries.filter((e) => e.switch).length;
    $("dInfo").innerHTML = `<span class="chip"><b>Floor</b>${esc(pnl.floor ?? "—")}</span><span class="chip"><b>Ports</b>${pnl.ports_total}</span><span class="chip"><b>Cabled</b>${used}</span>`;
    const byPort = new Map(pnl.entries.map((e) => [e.panel_port, e]));
    let cells = "";
    for (let i = 1; i <= pnl.ports_total; i++) {
      const e = byPort.get(i);
      let cls = "empty";
      if (e) { const [d, p] = swPort(e); cls = d && p ? portClass(d, p, akeys) : "down"; }
      cells += `<div class="fp ${cls} ${S.selPort === String(i) ? "sel" : ""}" data-pp="${i}">${i}</div>`;
    }
    $("dFace").innerHTML = `<span class="fp-label">${esc(pnl.name)}</span><div class="fp-group panel-group">${cells}</div>`;
    $("pHead").innerHTML = `<tr><th>Panel port</th><th>Location</th><th>Switch</th><th>Switch port</th><th>Description</th><th>Status</th><th>VLAN</th></tr>`;
    $("pBody").innerHTML = pnl.entries.map((e) => {
      const [d, p] = swPort(e);
      const c = d && p ? portClass(d, p, akeys) : "down";
      const pill = { up: "Up", down: "Down", alarm: "DOWN · ALARM", admin: "Shutdown" }[c];
      return `<tr class="${c === "alarm" ? "alarm" : ""} ${S.selPort === String(e.panel_port) ? "sel" : ""}" data-pp="${e.panel_port}" data-sw="${esc(e.switch)}" data-swp="${esc(e.switch_port)}">
        <td class="mono"><b>${e.panel_port}</b></td><td>${esc(e.location || "—")}</td>
        <td>${esc(e.switch || "—")}</td><td class="mono">${esc(e.switch_port || "—")}</td>
        <td class="desc">${p && p.alias ? esc(p.alias) : `<span class="muted">—</span>`}</td>
        <td><span class="pill ${c}">${pill}</span></td><td class="mono">${p ? (p.trunk ? "trunk" : p.vlan ?? "—") : "—"}</td></tr>`;
    }).join("");
  }

  // faceplate interaction
  const tip = $("tip");
  $("dFace").addEventListener("mousemove", (e) => {
    const el = e.target.closest(".fp");
    if (!el || !S.openDev) { tip.hidden = true; return; }
    let p, d;
    if (S.openDev.startsWith("panel:")) {
      const pnl = S.panels.find((x) => x.name === S.openDev.slice(6));
      const en = pnl && pnl.entries.find((x) => String(x.panel_port) === el.dataset.pp);
      if (!en) { tip.innerHTML = `<b>Port ${esc(el.dataset.pp)}</b>not cabled`; tip.hidden = false; }
      else {
        d = S.devices.get(en.switch); p = d && d.ports.find((x) => x.name === en.switch_port);
        tip.innerHTML = `<b>Panel port ${en.panel_port} → ${esc(en.switch)} ${esc(en.switch_port)}</b>${esc(en.location || "")}${p ? `<br>${esc(p.alias || "")} · ${esc(p.oper.toUpperCase())}` : ""}`;
        tip.hidden = false;
      }
    } else {
      d = S.devices.get(S.openDev);
      p = d && d.ports.find((x) => x.name === el.dataset.port);
      if (!p) return;
      tip.innerHTML = `<b>${esc(p.name)} — ${esc(p.oper.toUpperCase())}${p.admin !== "up" ? " (shutdown)" : ""}</b>
        ${p.alias ? esc(p.alias) + "<br>" : ""}${p.patch ? esc(patchText(p)) + "<br>" : ""}
        ${p.trunk ? "Trunk" : p.vlan != null ? "VLAN " + esc(p.vlan) : ""} ${p.oper === "up" ? "· " + fmtSpeed(p.speed) : ""}
        ${p.oper === "up" ? `<br>In ${fmtBps(p.in_bps)} · Out ${fmtBps(p.out_bps)}` : ""}${p.poe_w ? `<br>PoE ${p.poe_w} W` : ""}
        ${p.neighbor ? `<br>→ ${esc(p.neighbor.device)} ${esc(p.neighbor.port)}` : ""}`;
      tip.hidden = false;
    }
    tip.style.left = Math.min(e.clientX + 14, window.innerWidth - 330) + "px";
    tip.style.top = e.clientY + 14 + "px";
  });
  $("dFace").addEventListener("mouseleave", () => { tip.hidden = true; });
  const selectPort = (name) => {
    S.selPort = name; S.portFilter = "all"; $("pFilter").value = "";
    $("pSeg").querySelectorAll("button").forEach((x) => x.classList.toggle("active", x.dataset.f === "all"));
    renderDrawer(true); loadChart();
  };
  $("dFace").addEventListener("click", (e) => {
    const el = e.target.closest(".fp"); if (!el) return;
    if (S.openDev.startsWith("panel:")) { S.selPort = el.dataset.pp; renderDrawer(true); return; }
    selectPort(el.dataset.port);
  });
  $("pBody").addEventListener("click", (e) => {
    const tr = e.target.closest("tr"); if (!tr) return;
    if (tr.dataset.sw) { if (tr.dataset.sw) openDrawer(tr.dataset.sw, tr.dataset.swp); return; }
    if (tr.dataset.port) selectPort(tr.dataset.port);
  });

  // ------------------------------------------------------------------ traffic chart
  $("chartSeg").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    S.chartRange = b.dataset.r;
    $("chartSeg").querySelectorAll("button").forEach((x) => x.classList.toggle("active", x === b));
    loadChart();
  });
  async function loadChart() {
    const d = S.devices.get(S.openDev);
    const p = d && d.ports.find((x) => x.name === S.selPort);
    if (!p) return;
    $("chartBox").hidden = false;
    $("chartTitle").textContent = `${d.name} ${p.name}`;
    $("chartSub").textContent = [p.alias, patchText(p), p.speed ? fmtSpeed(p.speed) : ""].filter(Boolean).join(" · ");
    $("chart").innerHTML = `<div class="empty">Loading…</div>`;
    try {
      const h = await api(`/api/history?device=${encodeURIComponent(d.name)}&port=${encodeURIComponent(p.name)}&range=${S.chartRange}`);
      drawChart(h.points, p.speed, S.chartRange);
    } catch (e) { $("chart").innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
  }
  function drawChart(points, speedMbps, range) {
    const el = $("chart");
    if (!points.length) { el.innerHTML = `<div class="empty">No traffic history yet. Points appear every 5 minutes.</div>`; return; }
    const W = 900, H = 220, L = 64, R = 12, T = 12, B = 26;
    const t0 = points[0][0], t1 = Math.max(points[points.length - 1][0], t0 + 1);
    const peak = Math.max(...points.map((p) => Math.max(p[1], p[2])), 1);
    const nice = (v) => { const e = Math.pow(10, Math.floor(Math.log10(v))); for (const m of [1, 2, 2.5, 5, 10]) if (m * e >= v) return m * e; return 10 * e; };
    const ymax = nice(peak * 1.1);
    const x = (t) => L + (W - L - R) * (t - t0) / (t1 - t0), y = (v) => T + (H - T - B) * (1 - v / ymax);
    const path = (i) => points.map((p, k) => `${k ? "L" : "M"}${x(p[0]).toFixed(1)},${y(p[i]).toFixed(1)}`).join("");
    const area = (i) => `${path(i)}L${x(points[points.length - 1][0]).toFixed(1)},${y(0)}L${x(points[0][0]).toFixed(1)},${y(0)}Z`;
    let grid = "";
    for (let k = 0; k <= 4; k++) {
      const v = ymax * k / 4;
      grid += `<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" class="gl"/><text x="${L - 6}" y="${y(v) + 4}" class="yl">${fmtBps(v)}</text>`;
    }
    const fmtX = (t) => { const d = new Date(t * 1000);
      return range === "day" ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })
        : range === "week" ? d.toLocaleDateString([], { weekday: "short", day: "numeric" }) : d.toLocaleDateString([], { month: "short", day: "numeric" }); };
    for (let k = 0; k <= 5; k++) { const t = t0 + (t1 - t0) * k / 5; grid += `<text x="${x(t)}" y="${H - 6}" class="xl" text-anchor="${k === 0 ? "start" : k === 5 ? "end" : "middle"}">${fmtX(t)}</text>`; }
    const capLine = speedMbps && speedMbps * 1e6 <= ymax ? `<line x1="${L}" x2="${W - R}" y1="${y(speedMbps * 1e6)}" y2="${y(speedMbps * 1e6)}" class="cap"/>` : "";
    el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Traffic graph">
      ${grid}${capLine}
      <path d="${area(1)}" class="a-in"/><path d="${path(1)}" class="l-in"/>
      <path d="${path(2)}" class="l-out"/>
      <line id="cx" class="cursor" y1="${T}" y2="${H - B}" x1="-10" x2="-10"/>
    </svg>
    <div class="chart-legend"><span><i class="lg-in"></i>In (avg)</span><span><i class="lg-out"></i>Out (avg)</span>
      <span class="muted">Peak ${fmtBps(peak)}${speedMbps ? ` · ${(100 * peak / (speedMbps * 1e6)).toFixed(1)}% of ${fmtSpeed(speedMbps)}` : ""}</span><span id="cval" class="muted"></span></div>`;
    const svg = el.querySelector("svg");
    svg.addEventListener("mousemove", (ev) => {
      const r = svg.getBoundingClientRect();
      const t = t0 + (t1 - t0) * (((ev.clientX - r.left) / r.width * W) - L) / (W - L - R);
      let best = points[0]; for (const p of points) if (Math.abs(p[0] - t) < Math.abs(best[0] - t)) best = p;
      const cx = svg.querySelector("#cx"); cx.setAttribute("x1", x(best[0])); cx.setAttribute("x2", x(best[0]));
      $("cval").textContent = `${fmtTime(best[0])} · in ${fmtBps(best[1])} · out ${fmtBps(best[2])} · peak ${fmtBps(Math.max(best[3], best[4]))}`;
    });
  }

  // ------------------------------------------------------------------ views
  function setView(v) {
    S.view = v;
    document.querySelectorAll(".vtab[data-view]").forEach((b) => b.classList.toggle("active", b.dataset.view === v));
    document.querySelectorAll(".view").forEach((el) => { el.hidden = el.id !== `view-${v}`; });
    if (v === "overview") { needFit = true; renderTopology(); }
    if (v === "finder") { loadNew(); $("finderQ").focus(); }
    if (v === "health") renderHealth();
    if (v === "compliance") loadCompliance();
    store.set("netmon.view", v);
  }
  document.querySelectorAll(".vtab[data-view]").forEach((b) => b.addEventListener("click", () => setView(b.dataset.view)));

  // finder
  const macRow = (r) => `<tr data-dev="${esc(r.device)}" data-port="${esc(r.port)}">
      <td class="mono">${r.mac ? esc(r.mac) : `<span class="muted">no device</span>`}</td><td class="mono">${esc(r.ip || "—")}</td>
      <td><b>${esc(r.device)}</b></td><td class="mono">${esc(r.port)}</td><td class="mono">${r.vlan ?? "—"}</td>
      <td>${esc(r.description || "—")}</td>
      <td>${r.patch ? `${esc(r.patch.panel)}/${r.patch.panel_port} <span class="muted">${esc(r.patch.location || "")}</span>` : "—"}</td>
      <td><span class="pill ${r.port_status === "up" ? "up" : "down"}">${esc(r.port_status)}</span></td>
      <td class="muted">${r.last_seen ? ago(r.last_seen) : "—"}</td></tr>`;
  const macHead = `<thead><tr><th>MAC</th><th>IP</th><th>Switch</th><th>Port</th><th>VLAN</th><th>Description</th><th>Patch / location</th><th>Port</th><th>Last seen</th></tr></thead>`;
  $("finderForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const q = $("finderQ").value.trim();
    if (!q) return;
    $("finderTable").innerHTML = `<tbody><tr><td class="empty">Searching…</td></tr></tbody>`;
    const rows = await api(`/api/find?q=${encodeURIComponent(q)}`).catch(() => []);
    $("finderTable").innerHTML = rows.length ? macHead + `<tbody>${rows.map(macRow).join("")}</tbody>`
      : `<tbody><tr><td class="empty">Nothing found for “${esc(q)}”. MAC tables refresh every few minutes; a device that is switched off is not in them.</td></tr></tbody>`;
  });
  async function loadNew() {
    const r = await api("/api/inventory/new?hours=24").catch(() => ({ total: 0, new: [] }));
    $("finderCount").textContent = `${r.total} devices known`;
    $("newTable").innerHTML = r.new.length ? macHead + `<tbody>${r.new.map(macRow).join("")}</tbody>`
      : `<tbody><tr><td class="empty">No new devices in the last 24 hours.</td></tr></tbody>`;
  }
  ["finderTable", "newTable"].forEach((id) => $(id).addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-dev]"); if (tr) openDrawer(tr.dataset.dev, tr.dataset.port);
  }));

  // health
  function renderHealth() {
    if (S.view !== "health") return;
    const t = S.thresholds;
    const bar = (pct, limit) => pct == null ? "—" : `<div class="bar"><i style="width:${Math.min(100, pct)}%" class="${pct >= limit ? "hot" : pct >= limit * 0.8 ? "warm" : ""}"></i></div><span class="num">${Math.round(pct)}%</span>`;
    const st = { ok: `<span class="pill up">OK</span>`, warn: `<span class="pill warnp">WARNING</span>`, bad: `<span class="pill alarm">FAILED</span>`, na: "—" };
    const devs = [...S.devices.values()].sort((a, b) => (a.role === b.role ? a.floor - b.floor || a.name.localeCompare(b.name) : a.role === "core" ? -1 : 1));
    $("healthTable").innerHTML = `<thead><tr><th>Switch</th><th>Status</th><th>CPU</th><th>Memory</th><th>Temperature</th><th>Fans</th><th>Power</th><th>PoE</th><th>Uptime</th></tr></thead><tbody>` +
      devs.map((d) => {
        const h = healthSummary(d);
        const poePct = h.poe && h.poe.budget_w ? 100 * h.poe.used_w / h.poe.budget_w : null;
        return `<tr data-dev="${esc(d.name)}"><td><b>${esc(d.name)}</b><div class="muted small">${esc(d.host)}</div></td>
          <td><span class="sdot ${d.status}"></span></td>
          <td class="barcell">${bar(h.cpu, t.cpu_percent || 90)}</td>
          <td class="barcell">${bar(h.mem, t.memory_percent || 90)}</td>
          <td>${h.temp != null ? `${h.temp}°C ` : ""}${h.temp != null ? st[h.tempState] : "—"}</td>
          <td>${h.fans ? st[h.fanState] : "—"}</td><td>${h.psus ? st[h.psuState] : "—"}</td>
          <td class="barcell">${h.poe ? `${bar(poePct, t.poe_budget_percent || 90)}<div class="muted small">${Math.round(h.poe.used_w)} / ${Math.round(h.poe.budget_w)} W</div>` : "—"}</td>
          <td class="muted">${d.uptime ? fmtDur(d.uptime) : "—"}</td></tr>`;
      }).join("") + "</tbody>";
    $("healthNote").textContent = `Warnings at CPU ${t.cpu_percent}% · memory ${t.memory_percent}% · PoE ${t.poe_budget_percent}% of budget`;
  }
  $("healthTable").addEventListener("click", (e) => { const tr = e.target.closest("tr[data-dev]"); if (tr) openDrawer(tr.dataset.dev); });

  // compliance
  let compOpen = new Set();
  async function loadCompliance() {
    const rows = await api("/api/compliance").catch(() => []);
    const icon = { pass: "✅", warn: "🟠", fail: "❌", unknown: "➖" };
    $("compTable").innerHTML = `<thead><tr><th>Switch</th><th>Score</th><th class="num">Failed</th><th class="num">Warnings</th><th>Checks</th></tr></thead><tbody>` +
      rows.map((r) => `<tr class="comp-row" data-dev="${esc(r.device)}"><td><b>${esc(r.device)}</b> <span class="muted small">${esc(r.host)}</span></td>
        <td><span class="score ${r.score == null ? "" : r.score >= 90 ? "good" : r.score >= 70 ? "mid" : "bad"}">${r.score == null ? "—" : r.score + "%"}</span></td>
        <td class="num">${r.fails || ""}</td><td class="num">${r.warns || ""}</td>
        <td>${r.checks.map((c) => icon[c.status]).join(" ")}</td></tr>
        <tr class="comp-detail" ${compOpen.has(r.device) ? "" : "hidden"}><td colspan="5"><ul class="checks">${r.checks.map((c) =>
          `<li class="${c.status}"><span>${icon[c.status]}</span><b>${esc(c.title)}</b><span class="muted">${esc(c.detail)}</span></li>`).join("")}</ul></td></tr>`).join("") + "</tbody>";
  }
  $("compTable").addEventListener("click", (e) => {
    const tr = e.target.closest("tr.comp-row"); if (!tr) return;
    const det = tr.nextElementSibling; det.hidden = !det.hidden;
    if (det.hidden) compOpen.delete(tr.dataset.dev); else compOpen.add(tr.dataset.dev);
  });

  $("demoFail").onclick = () => api("/api/demo/fail", { method: "POST" }).catch(() => {});

  // ------------------------------------------------------------------ render scheduling
  let pending = null;
  function render() {
    if (pending) return;
    pending = setTimeout(() => {
      pending = null;
      renderStats(); renderAlarms(); renderEvents();
      if (S.view === "overview") { renderTopology(); renderFloors(); }
      if (S.view === "health") renderHealth();
      if (S.openDev) renderDrawer();
    }, 150);
  }

  // ------------------------------------------------------------------ websocket
  let retry = 1000;
  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/ws`);
    ws.onopen = () => { retry = 1000; $("conn").className = "conn ok"; $("connText").textContent = "Live"; };
    ws.onclose = (ev) => {
      if (ev.code === 4401) { location.href = "/login"; return; }
      $("conn").className = "conn bad"; $("connText").textContent = "Disconnected – retrying…";
      setTimeout(connect, retry); retry = Math.min(retry * 2, 10000);
    };
    ws.onmessage = (m) => handle(JSON.parse(m.data));
  }
  function handle(msg) {
    const d = msg.data;
    switch (msg.type) {
      case "state":
        S.devices = new Map(d.devices.map((x) => [x.name, x]));
        S.links = d.links; S.alarms = new Map(d.alarms.map((a) => [a.id, a]));
        S.events = d.events; S.demo = d.demo; S.panels = d.panels || []; S.thresholds = d.thresholds || {};
        applyRole();
        break;
      case "device": S.devices.set(d.name, d); break;
      case "links": S.links = d; break;
      case "event":
        S.events.unshift(d); newEventIds.add(d.id);
        if (S.events.length > 500) S.events.length = 500;
        break;
      case "alarm_raised": S.alarms.set(d.id, d); beep(d.severity !== "critical"); break;
      case "alarm_updated": if (S.alarms.has(d.id)) S.alarms.set(d.id, d); break;
      case "alarm_cleared": S.alarms.delete(d.id); break;
    }
    render();
  }

  api("/api/me").then((me) => { S.me = me; applyRole(); }).catch(() => {});
  connect();
  const startView = store.get("netmon.view", "overview");
  if (startView !== "overview" && $(`view-${startView}`)) setView(startView);
})();
