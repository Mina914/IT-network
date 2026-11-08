(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  fetch("/api/auth/status").then((r) => r.json()).then((s) => {
    if (!s.enabled) location.href = "/";
    $("nousers").hidden = s.has_users;
  }).catch(() => {});
  $("f").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("go").disabled = true;
    $("msg").hidden = true;
    try {
      const r = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Requested-With": "netmon" },
        body: JSON.stringify({ username: $("u").value.trim(), password: $("p").value }),
      });
      if (r.ok) { location.href = "/"; return; }
      const d = await r.json().catch(() => ({}));
      $("msg").textContent = r.status === 429 ? "Too many failed attempts. Wait a few minutes and try again."
        : d.detail || "Sign-in failed.";
      $("msg").hidden = false;
      $("p").value = "";
      $("p").focus();
    } catch {
      $("msg").textContent = "Can't reach the NetMon server.";
      $("msg").hidden = false;
    } finally {
      $("go").disabled = false;
    }
  });
})();
