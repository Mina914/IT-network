/* NetMon dashboard */
(() => {
  "use strict";

  // ------------------------------------------------------------------ state
  const S = {
    devices: new Map(),       // name -> device
    links: [],
    alarms: new Map(),        // id -> active alarm
    events: [],
    demo: false,
    openDev: null,
    selPort: null,
    portFilter: "all",
  };
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const store = {
    get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : v; } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
  };

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
  const model = (d) => {
    const m = (d.sysdescr || "").match(/\(([^)]+)\)/);
    return m ? m[1] : "";
  };

  // ------------------------------------------------------------------ helpers
  const linkPortSet = () => {
    const s = new Set();
    for (const l of S.links) { s.add(`${l.a_device}|${l.a_port}`); s.add(`${l.b_device}|${l.b_port}`); }
    return s;
  };
  const alarmKeys = () => new Set([...S.alarms.values()].map((a) => a.key));
  const portClass = (dev, p, akeys) => {
    if (p.admin !== "up") return "admin";
    if (akeys.has(`${dev.name}|${p.name}`)) return "alarm";
    return p.oper === "up" ? "up" : "down";
  };
  const physical = (p) => !/^(Po|Vl|Lo|Tu|Nu)/i.test(p.name);

  // ------------------------------------------------------------------ topology
  const COLORS = {
    up:      { background: "#0f2a1d", border: "#22c55e", highlight: { background: "#14402a", border: "#4ade80" }, hover: { background: "#14402a", border: "#4ade80" } },
    warning: { background: "#2b2210", border: "#f59e0b", highlight: { background: "#3d2f12", border: "#fbbf24" }, hover: { background: "#3d2f12", border: "#fbbf24" } },
    down:    { background: "#2d1111", border: "#ef4444", highlight: { background: "#451616", border: "#f87171" }, hover: { background: "#451616", border: "#f87171" } },
    unknown: { background: "#172033", border: "#64748b", highlight: { background: "#1e293b", border: "#94a3b8" }, hover: { background: "#1e293b", border: "#94a3b8" } },
  };
  const nodes = new vis.DataSet();
  const edges = new vis.DataSet();
  let floorLabels = [];
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
      floorLabels.push({ text: `FLOOR ${floors[gi]}`, x: (x0 + x - SW) / 2, y: yAcc + 50 });
      x += FG;
    });
    return pos;
  }

  function devTitle(d) {
    const alarms = [...S.alarms.values()].filter((a) => a.device === d.name).length;
    return [
      `${d.name}  (${d.host})`,
      model(d) && `Model: ${model(d)}`,
      `Status: ${d.status.toUpperCase()}`,
      `Ports up: ${d.ports_up}/${d.ports_total}`,
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
      const n = {
        id: d.name,
        label: `<b>${d.name}</b>\n${d.host}`,
        color: COLORS[d.status] || COLORS.unknown,
        title: devTitle(d),
        borderWidth: d.status === "down" ? 3 : 2,
      };
      if (!existing.has(d.name)) Object.assign(n, pos[d.name]);
      return n;
    });
    nodes.update(upd);
    const keep = new Set(devs.map((d) => d.name));
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
    edges.update(eu);
    const ekeep = new Set(eu.map((e) => e.id));
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

  // blink broken links
  let blinkOn = false;
  setInterval(() => {
    blinkOn = !blinkOn;
    const down = edges.get({ filter: (e) => e._down });
    if (down.length) edges.update(down.map((e) => ({ id: e.id, color: { ...e.color, color: blinkOn ? "#ef4444" : "#5b1a1a" } })));
  }, 600);

  // ------------------------------------------------------------------ header stats
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
    $("stAlarms").textContent = n;
    $("stAlarmBox").classList.toggle("on", n > 0);
    $("alarmCount").textContent = n;
    $("alarmCount").classList.toggle("hot", n > 0);
    document.title = n ? `(${n}) 🔴 NetMon` : "NetMon";
    $("demoBadge").hidden = !S.demo;
    $("demoFail").hidden = !S.demo;
  }

  // ------------------------------------------------------------------ alarms
  function renderAlarms() {
    const list = [...S.alarms.values()].sort((a, b) => b.raised_ts - a.raised_ts);
    const el = $("alarmList");
    if (!list.length) {
      el.innerHTML = `<div class="empty"><span class="big">✅</span>No active alarms. All monitored links are up.</div>`;
    } else {
      el.innerHTML = list.map((a) => `
        <div class="alarm-item ${a.acked_by ? "acked" : ""}" data-dev="${esc(a.device)}" data-port="${esc(a.port || "")}">
          <div class="row1">
            <div class="msg">${a.port ? "🔴" : "⛔"} ${esc(a.message)}</div>
            <div class="dur" data-since="${a.raised_ts}">${fmtDur(Date.now() / 1000 - a.raised_ts)}</div>
          </div>
          <div class="meta">Since ${fmtTime(a.raised_ts)}${a.acked_by ? ` · Acknowledged by <b>${esc(a.acked_by)}</b>` : ""}</div>
          ${a.acked_by ? "" : `<div style="margin-top:8px"><button class="btn small danger" data-ack="${a.id}">Acknowledge</button></div>`}
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

  function operator() {
    let n = store.get("netmon.operator", "");
    if (!n) {
      n = (prompt("Your name (shown on acknowledged alarms):", "") || "").trim();
      if (n) store.set("netmon.operator", n);
    }
    return n || "operator";
  }
  async function doAck(ids) {
    const by = operator();
    for (const id of ids) {
      await fetch(`/api/alarms/${id}/ack`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ by }) });
    }
  }

  function renderBanner() {
    const un = [...S.alarms.values()].filter((a) => !a.acked_by).sort((a, b) => b.raised_ts - a.raised_ts);
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
  soundBtn.onclick = () => {
    soundOn = !soundOn; store.set("netmon.sound", soundOn ? "1" : "0"); paintSound();
    if (soundOn) { ensureAudio(); beep(); }
  };
  function ensureAudio() {
    if (!audio) { try { audio = new (window.AudioContext || window.webkitAudioContext)(); } catch { audio = null; } }
    if (audio && audio.state === "suspended") audio.resume();
  }
  function beep() {
    if (!soundOn) return;
    ensureAudio();
    if (!audio) return;
    const t0 = audio.currentTime;
    [[880, 0], [660, 0.22], [880, 0.44], [660, 0.66]].forEach(([f, t]) => {
      const o = audio.createOscillator(), g = audio.createGain();
      o.type = "square"; o.frequency.value = f;
      g.gain.setValueAtTime(0.0001, t0 + t);
      g.gain.exponentialRampToValueAtTime(0.12, t0 + t + 0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, t0 + t + 0.2);
      o.connect(g).connect(audio.destination);
      o.start(t0 + t); o.stop(t0 + t + 0.21);
    });
  }
  document.addEventListener("click", () => { if (soundOn) ensureAudio(); }, { once: true });
  // keep reminding while alarms are unacknowledged
  setInterval(() => { if ([...S.alarms.values()].some((a) => !a.acked_by)) beep(); }, 20000);

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
      d.ports.some((p) => `${p.name} ${p.alias}`.toLowerCase().includes(q)));
    const groups = new Map();
    for (const d of devs) {
      const k = d.role === "core" ? "Core / Server room" : d.role === "distribution" ? "Distribution" : `Floor ${d.floor}`;
      const order = d.role === "core" ? -2 : d.role === "distribution" ? -1 : d.floor;
      if (!groups.has(k)) groups.set(k, { order, list: [] });
      groups.get(k).list.push(d);
    }
    const html = [...groups.entries()].sort((a, b) => a[1].order - b[1].order).map(([k, g]) => `
      <div class="floor">
        <div class="floor-title">${esc(k)}</div>
        <div class="sw-grid">
          ${g.list.sort((a, b) => a.name.localeCompare(b.name)).map((d) => {
            const al = [...S.alarms.values()].filter((a) => a.device === d.name).length;
            const ports = d.ports.filter(physical);
            return `
            <div class="sw ${d.status}" data-dev="${esc(d.name)}">
              <div class="sw-head"><span class="sw-name">${esc(d.name)}</span><span class="sw-ip">${esc(d.host)}</span></div>
              <div class="sw-meta">
                <span>${d.status === "down" ? "⛔ UNREACHABLE" : d.status === "unknown" ? "⏳ waiting for first poll" : `${d.ports_up}/${d.ports_total} ports up`}</span>
                ${al ? `<span style="color:var(--down)">🔴 ${al} alarm${al > 1 ? "s" : ""}</span>` : ""}
                ${d.uptime ? `<span>up ${fmtDur(d.uptime)}</span>` : ""}
                ${model(d) ? `<span>${esc(model(d))}</span>` : ""}
              </div>
              <div class="mini">${ports.map((p) => `<i class="${portClass(d, p, akeys)}"></i>`).join("")}</div>
            </div>`;
          }).join("")}
        </div>
      </div>`).join("");
    $("floors").innerHTML = html || `<div class="empty">No switches match.</div>`;
  }
  $("swFilter").addEventListener("input", renderFloors);
  $("floors").addEventListener("click", (e) => {
    const c = e.target.closest(".sw");
    if (c) openDrawer(c.dataset.dev);
  });

  // ------------------------------------------------------------------ device drawer
  function openDrawer(name, port = null) {
    if (!S.devices.has(name)) return;
    S.openDev = name;
    S.selPort = port;
    $("pFilter").value = "";
    $("drawer").hidden = false;
    renderDrawer(true);
  }
  function closeDrawer() { S.openDev = null; $("drawer").hidden = true; }
  $("drawer").addEventListener("click", (e) => { if (e.target.closest("[data-close]")) closeDrawer(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  $("dPoll").onclick = async () => {
    if (!S.openDev) return;
    $("dPoll").textContent = "↻ Polling…";
    await fetch(`/api/devices/${encodeURIComponent(S.openDev)}/poll`, { method: "POST" });
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
    const d = S.devices.get(S.openDev);
    if (!d) return;
    const akeys = alarmKeys(), lp = linkPortSet();
    $("dStatus").className = `sdot ${d.status}`;
    $("dName").textContent = d.name;
    $("dSub").textContent = [d.sysname, d.sysdescr].filter(Boolean).join(" · ") || "Waiting for first poll…";
    const chips = [
      ["IP", d.host], ["Role", d.role], ["Floor", d.role === "core" ? "Core" : d.floor],
      ["Ports up", `${d.ports_up}/${d.ports_total}`], ["Uptime", d.uptime ? fmtDur(d.uptime) : "—"],
      ["Last poll", ago(d.last_poll)],
    ];
    $("dInfo").innerHTML = chips.map(([k, v]) => `<span class="chip"><b>${k}</b>${esc(v)}</span>`).join("") +
      (d.last_error ? `<span class="chip err"><b>Error</b>${esc(d.last_error)}</span>` : "");

    // faceplate: group by interface type + module (Gi1/0/, Te1/1/ ...)
    const groups = new Map();
    for (const p of d.ports.filter(physical)) {
      const m = p.name.match(/^(.*?)(\d+)$/);
      const k = m ? m[1] : p.name;
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push({ p, n: m ? m[2] : "" });
    }
    $("dFace").innerHTML = [...groups.entries()].map(([k, list]) => {
      const sfp = /^(Te|Twe|Fo|Hu|Tw)/.test(k);
      const single = list.length <= 4;
      return `<span class="fp-label">${esc(k)}</span><div class="fp-group ${single ? "single" : ""}">${list.map(({ p, n }) =>
        `<div class="fp ${portClass(d, p, akeys)} ${sfp ? "sfp" : ""} ${S.selPort === p.name ? "sel" : ""}" data-port="${esc(p.name)}">${n}</div>`).join("")}</div>`;
    }).join("");

    const q = $("pFilter").value.trim().toLowerCase();
    const rows = d.ports.filter((p) => {
      if (q && !`${p.name} ${p.descr} ${p.alias} ${p.vlan ?? ""} ${p.neighbor ? p.neighbor.device : ""}`.toLowerCase().includes(q)) return false;
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
      const isUp = lp.has(`${d.name}|${p.name}`);
      return `<tr class="${c === "alarm" ? "alarm" : ""} ${S.selPort === p.name ? "sel" : ""}" data-port="${esc(p.name)}">
        <td class="mono"><b>${esc(p.name)}</b>${isUp ? `<span class="tag">UPLINK</span>` : ""}</td>
        <td class="desc">${p.alias ? esc(p.alias) : `<span class="muted">—</span>`}</td>
        <td><span class="pill ${c}">${pill}</span></td>
        <td class="mono">${p.trunk ? "trunk" : p.vlan ?? "—"}</td>
        <td class="mono">${p.oper === "up" ? fmtSpeed(p.speed) : "—"}</td>
        <td class="num">${p.oper === "up" ? fmtBps(p.in_bps) : "—"}</td>
        <td class="num">${p.oper === "up" ? fmtBps(p.out_bps) : "—"}</td>
        <td class="num ${p.in_errors + p.out_errors ? "err-n" : "muted"}">${p.in_errors + p.out_errors}</td>
        <td>${p.neighbor ? `${esc(p.neighbor.device.split(".")[0])} <span class="muted mono">${esc(p.neighbor.port)}</span>` : `<span class="muted">—</span>`}</td>
        <td class="muted">${p.last_change ? ago(p.last_change) : "—"}</td>
      </tr>`;
    }).join("") || `<tr><td colspan="10" class="empty">No ports match.</td></tr>`;

    if (scroll && S.selPort) {
      const tr = $("pBody").querySelector(`tr[data-port="${CSS.escape(S.selPort)}"]`);
      if (tr) tr.scrollIntoView({ block: "center" });
    }
  }

  // faceplate interaction
  const tip = $("tip");
  $("dFace").addEventListener("mousemove", (e) => {
    const el = e.target.closest(".fp");
    const d = S.devices.get(S.openDev);
    if (!el || !d) { tip.hidden = true; return; }
    const p = d.ports.find((x) => x.name === el.dataset.port);
    if (!p) return;
    tip.innerHTML = `<b>${esc(p.name)} — ${esc(p.oper.toUpperCase())}${p.admin !== "up" ? " (shutdown)" : ""}</b>
      ${p.alias ? esc(p.alias) + "<br>" : ""}
      ${p.trunk ? "Trunk" : p.vlan != null ? "VLAN " + esc(p.vlan) : ""} ${p.oper === "up" ? "· " + fmtSpeed(p.speed) : ""}
      ${p.oper === "up" ? `<br>In ${fmtBps(p.in_bps)} · Out ${fmtBps(p.out_bps)}` : ""}
      ${p.neighbor ? `<br>→ ${esc(p.neighbor.device)} ${esc(p.neighbor.port)}` : ""}`;
    tip.hidden = false;
    tip.style.left = Math.min(e.clientX + 14, window.innerWidth - 330) + "px";
    tip.style.top = e.clientY + 14 + "px";
  });
  $("dFace").addEventListener("mouseleave", () => { tip.hidden = true; });
  $("dFace").addEventListener("click", (e) => {
    const el = e.target.closest(".fp"); if (!el) return;
    S.selPort = el.dataset.port;
    S.portFilter = "all"; $("pFilter").value = "";
    $("pSeg").querySelectorAll("button").forEach((x) => x.classList.toggle("active", x.dataset.f === "all"));
    renderDrawer(true);
  });
  $("pBody").addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-port]"); if (!tr) return;
    S.selPort = tr.dataset.port; renderDrawer();
  });

  $("demoFail").onclick = () => fetch("/api/demo/fail", { method: "POST" });

  // ------------------------------------------------------------------ render scheduling
  let pending = null;
  function render() {
    if (pending) return;
    pending = setTimeout(() => {
      pending = null;
      renderStats(); renderTopology(); renderAlarms(); renderFloors(); renderEvents();
      if (S.openDev) renderDrawer();
    }, 150);
  }

  // ------------------------------------------------------------------ websocket
  let ws, retry = 1000;
  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/ws`);
    ws.onopen = () => { retry = 1000; $("conn").className = "conn ok"; $("connText").textContent = "Live"; };
    ws.onclose = () => {
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
        S.links = d.links;
        S.alarms = new Map(d.alarms.map((a) => [a.id, a]));
        S.events = d.events;
        S.demo = d.demo;
        break;
      case "device": S.devices.set(d.name, d); break;
      case "links": S.links = d; break;
      case "event":
        S.events.unshift(d); newEventIds.add(d.id);
        if (S.events.length > 500) S.events.length = 500;
        break;
      case "alarm_raised": S.alarms.set(d.id, d); beep(); break;
      case "alarm_updated": if (S.alarms.has(d.id)) S.alarms.set(d.id, d); break;
      case "alarm_cleared": S.alarms.delete(d.id); break;
    }
    render();
  }

  connect();
})();
