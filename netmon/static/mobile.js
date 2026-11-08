(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const S = { devices: new Map(), links: [], alarms: new Map() };
  let role = "admin";
  const dur = (s) => { s = Math.max(0, Math.floor(s)); const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60);
    return h >= 24 ? `${Math.floor(h / 24)}d ${h % 24}h` : h ? `${h}h ${m}m` : m ? `${m}m` : `${s}s`; };

  function render() {
    const al = [...S.alarms.values()].sort((a, b) => (a.severity === b.severity ? b.raised_ts - a.raised_ts : a.severity === "critical" ? -1 : 1));
    const crit = al.filter((a) => a.severity === "critical").length;
    $("nAl").textContent = al.length;
    $("sAl").className = "stat " + (crit ? "hot" : al.length ? "warm" : "");
    const devs = [...S.devices.values()];
    $("nSw").textContent = `${devs.filter((d) => d.status !== "down").length}/${devs.length}`;
    $("nLk").textContent = `${S.links.filter((l) => l.status === "up").length}/${S.links.length}`;
    document.title = al.length ? `(${al.length}) NetMon` : "NetMon";
    $("alarms").innerHTML = al.length ? al.map((a) => `
      <div class="al ${a.severity} ${a.acked_by ? "acked" : ""}">
        <div class="m">${a.severity === "warning" ? "🟠" : "🔴"} ${esc(a.message)}</div>
        <div class="t"><span>${new Date(a.raised_ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
          <span>${dur(Date.now() / 1000 - a.raised_ts)}${a.acked_by ? ` · ack ${esc(a.acked_by)}` : ""}</span></div>
        ${!a.acked_by && role === "admin" ? `<button data-ack="${a.id}">Acknowledge</button>` : ""}
      </div>`).join("") : `<div class="none">✅ No active alarms</div>`;
    const order = { down: 0, warning: 1, unknown: 2, up: 3 };
    $("switches").innerHTML = devs.sort((a, b) => order[a.status] - order[b.status] || a.name.localeCompare(b.name)).map((d) => `
      <div class="sw ${d.status}"><span class="d"></span><span class="n">${esc(d.name)}</span>
        <span class="x">${d.status === "down" ? "UNREACHABLE" : `${d.ports_up}/${d.ports_total} ports${d.health && d.health.cpu != null ? ` · CPU ${Math.round(d.health.cpu)}%` : ""}`}</span></div>`).join("");
  }
  $("alarms").addEventListener("click", async (e) => {
    const b = e.target.closest("[data-ack]"); if (!b) return;
    b.disabled = true;
    await fetch(`/api/alarms/${b.dataset.ack}/ack`, { method: "POST", headers: { "X-Requested-With": "netmon" } });
  });
  let retry = 1000;
  function connect() {
    const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
    ws.onopen = () => { retry = 1000; $("conn").className = "conn ok"; $("connText").textContent = "Live"; };
    ws.onclose = (ev) => {
      if (ev.code === 4401) { location.href = "/login"; return; }
      $("conn").className = "conn bad"; $("connText").textContent = "Reconnecting…";
      setTimeout(connect, retry); retry = Math.min(retry * 2, 10000);
    };
    ws.onmessage = (m) => {
      const { type, data: d } = JSON.parse(m.data);
      if (type === "state") { S.devices = new Map(d.devices.map((x) => [x.name, x])); S.links = d.links; S.alarms = new Map(d.alarms.map((a) => [a.id, a])); }
      else if (type === "device") S.devices.set(d.name, d);
      else if (type === "links") S.links = d;
      else if (type === "alarm_raised" || type === "alarm_updated") S.alarms.set(d.id, d);
      else if (type === "alarm_cleared") S.alarms.delete(d.id);
      else return;
      render();
    };
  }
  fetch("/api/me").then((r) => r.json()).then((me) => { role = me.role; render(); }).catch(() => {});
  setInterval(render, 30000);
  connect();
})();
