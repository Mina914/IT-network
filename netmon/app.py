"""Web server: REST API + WebSocket live updates + background pollers."""
from __future__ import annotations

import asyncio
import logging
import socket
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import compliance, reports
from .auth import COOKIE, Auth, AuthError
from .config import Config
from .db import Database
from .history import History
from .inventory import Inventory
from .monitor import Monitor
from .notify import Notifier
from .patchpanels import PatchPanels

log = logging.getLogger("netmon")
STATIC = Path(__file__).parent / "static"

# Pages and files reachable without logging in (the login page itself).
PUBLIC = {"/login", "/api/login", "/api/auth/status", "/static/login.js", "/static/login.css"}
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                               "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
                               "base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class Login(BaseModel):
    username: str
    password: str


class PollScheduler:
    def __init__(self, monitor: Monitor, backend, interval: int):
        self.monitor = monitor
        self.backend = backend
        self.interval = interval
        self.wake: dict[str, asyncio.Event] = {}
        self.tasks: list[asyncio.Task] = []

    def poll_now(self, name: str):
        if name in self.wake:
            self.wake[name].set()

    async def _loop(self, dev, offset: float):
        await asyncio.sleep(offset)          # spread polls out
        ev = self.wake[dev.name]
        while True:
            ev.clear()
            ok = True
            try:
                snap = await asyncio.wait_for(self.backend.poll(dev), timeout=max(20, self.interval))
                self.monitor.apply_snapshot(dev.name, snap)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                ok = False
                msg = str(e) or e.__class__.__name__
                log.warning("poll %s (%s) failed: %s", dev.name, dev.host, msg)
                self.monitor.apply_poll_failure(dev.name, msg)
            wait = self.interval if ok else min(self.interval, 10)
            try:
                await asyncio.wait_for(ev.wait(), timeout=wait)
                await asyncio.sleep(1)       # small debounce after a syslog burst
            except asyncio.TimeoutError:
                pass

    def start(self, devices):
        n = max(len(devices), 1)
        for i, dev in enumerate(devices):
            self.wake[dev.name] = asyncio.Event()
            self.tasks.append(asyncio.create_task(self._loop(dev, i * min(self.interval, 10) / n)))
        self.monitor.poll_request = self.poll_now

    def stop(self):
        for t in self.tasks:
            t.cancel()


async def _fdb_loop(backend, devices, inventory: Inventory, interval: int, first_delay: float):
    await asyncio.sleep(first_delay)
    while True:
        for dev in devices:
            if inventory.monitor.devices[dev.name].reachable is not True:
                continue
            try:
                res = await asyncio.wait_for(backend.poll_fdb(dev), timeout=120)
                inventory.apply(dev.name, res["macs"], res["arp"])
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("MAC/ARP table of %s failed: %s", dev.name, str(e) or e.__class__.__name__)
        await asyncio.sleep(interval)


def create_app(cfg: Config) -> FastAPI:
    db = Database(cfg.db_path)
    notifier = Notifier(cfg.alerts, cfg.dashboard_url)
    monitor = Monitor(cfg, db, notifier)
    auth = Auth(db, cfg.auth)
    history = History(db, cfg.history)
    inventory = Inventory(db, monitor, cfg.inventory)
    monitor.history = history

    sim = None
    if cfg.demo:
        from .simulator import Simulator
        sim = Simulator(monitor)
        devices = sim.devices
        monitor.panels = PatchPanels(sim.patch_rows(), {d.name: d.floor for d in devices})
    else:
        devices = cfg.devices
        monitor.panels = PatchPanels.load(cfg.patch_panels_csv, {d.name for d in devices},
                                          {d.name: d.floor for d in devices})
    for d in devices:
        monitor.add_device(d)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        background = []
        if sim is not None:
            backend = sim
            background.append(asyncio.create_task(sim.run()))
            await asyncio.to_thread(sim.backfill_history, history)
            log.info("DEMO MODE: simulating %d switches", len(devices))
        else:
            from .snmp import SnmpBackend
            backend = SnmpBackend()
        for d in devices:
            try:
                d.resolved_ip = socket.gethostbyname(d.host)
            except OSError:
                d.resolved_ip = d.host

        scheduler = PollScheduler(monitor, backend, cfg.poll_interval)
        scheduler.start(devices)
        app.state.scheduler = scheduler
        if cfg.inventory.enabled:
            interval = 60 if cfg.demo else cfg.inventory.interval_seconds
            background.append(asyncio.create_task(
                _fdb_loop(backend, devices, inventory, interval, 8 if cfg.demo else 45)))

        syslog_transport = None
        if cfg.syslog_enabled and not cfg.demo:
            from .syslog import start_syslog
            try:
                syslog_transport = await start_syslog(monitor, "0.0.0.0", cfg.syslog_port)
            except OSError as e:
                log.error("could not start syslog on udp/%s: %s", cfg.syslog_port, e)

        if cfg.auth.enabled and not auth.has_users():
            log.warning("no dashboard users yet: create one with  python -m netmon -c <config> user add <name> --role admin")

        async def housekeeping():
            while True:
                await asyncio.sleep(600)
                try:
                    history.rollup()
                    db.prune_events(90)
                except Exception as e:
                    log.error("housekeeping failed: %s", e)
        background.append(asyncio.create_task(housekeeping()))

        yield
        scheduler.stop()
        for t in background:
            t.cancel()
        history.flush()
        if syslog_transport:
            syslog_transport.close()

    app = FastAPI(title="NetMon", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.monitor = monitor
    app.state.auth = auth
    app.state.sim = sim

    def user_of(request: Request) -> dict:
        return request.state.user

    def require_admin(request: Request):
        if user_of(request)["role"] != "admin":
            raise HTTPException(403, "admin role required")

    @app.middleware("http")
    async def security(request: Request, call_next):
        path = request.url.path
        user = None
        if cfg.auth.enabled:
            user = auth.session(request.cookies.get(COOKIE))
            if user is None and path not in PUBLIC:
                resp = (JSONResponse({"detail": "login required"}, 401) if path.startswith("/api/")
                        else RedirectResponse("/login", 303))
                resp.headers.update(SECURITY_HEADERS)
                return resp
        request.state.user = user or {"username": "demo" if cfg.demo else "local", "role": "admin"}
        # every state-changing request must come from our own pages (blocks cross-site requests)
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("x-requested-with") != "netmon":
            resp = JSONResponse({"detail": "missing X-Requested-With header"}, 403)
        else:
            resp = await call_next(request)
        resp.headers.update(SECURITY_HEADERS)
        return resp

    # ------------------------------------------------------------------ pages
    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/login")
    async def login_page():
        return FileResponse(STATIC / "login.html")

    @app.get("/m")
    async def mobile_page():
        return FileResponse(STATIC / "mobile.html")

    @app.get("/report")
    async def report_page():
        return FileResponse(STATIC / "report.html")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    # ------------------------------------------------------------------ auth
    @app.get("/api/auth/status")
    async def auth_status():
        return {"enabled": cfg.auth.enabled, "has_users": auth.has_users() if cfg.auth.enabled else True}

    @app.post("/api/login")
    async def login(body: Login, request: Request):
        if not cfg.auth.enabled:
            return {"ok": True}
        client = request.client.host if request.client else ""
        try:
            token = await asyncio.to_thread(auth.login, body.username.strip(), body.password, client)
        except AuthError as e:
            raise HTTPException(429, str(e))
        if not token:
            log.warning("failed login for %r from %s", body.username[:50], client)
            raise HTTPException(401, "wrong username or password")
        log.info("login: %s from %s", body.username, client)
        resp = JSONResponse({"ok": True})
        resp.set_cookie(COOKIE, token, max_age=cfg.auth.session_hours * 3600, httponly=True,
                        samesite="strict", secure=cfg.auth.secure_cookies, path="/")
        return resp

    @app.post("/api/logout")
    async def logout(request: Request):
        auth.logout(request.cookies.get(COOKIE))
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(COOKIE, path="/")
        return resp

    @app.get("/api/me")
    async def me(request: Request):
        return {**user_of(request), "auth_enabled": cfg.auth.enabled, "demo": cfg.demo}

    # ------------------------------------------------------------------ monitoring
    @app.get("/api/state")
    async def state():
        return monitor.state()

    @app.get("/api/devices/{name}")
    async def device(name: str):
        d = monitor.devices.get(name)
        if not d:
            raise HTTPException(404, "unknown device")
        return monitor.device_dict(d)

    @app.post("/api/devices/{name}/poll")
    async def poll(name: str, request: Request):
        require_admin(request)
        if name not in monitor.devices:
            raise HTTPException(404, "unknown device")
        app.state.scheduler.poll_now(name)
        return {"ok": True}

    @app.get("/api/events")
    async def events(limit: int = 200, device: str | None = None):
        return db.recent_events(min(limit, 2000), device)

    @app.get("/api/alarms")
    async def alarms(history: bool = False):
        return db.alarm_history(500) if history else db.active_alarms()

    @app.post("/api/alarms/{alarm_id}/ack")
    async def ack(alarm_id: int, request: Request):
        require_admin(request)
        alarm = monitor.ack(alarm_id, user_of(request)["username"])
        if not alarm:
            raise HTTPException(404, "unknown alarm")
        return alarm

    @app.get("/api/links")
    async def links():
        return monitor.links()

    @app.delete("/api/links/{link_id}")
    async def delete_link(link_id: int, request: Request):
        require_admin(request)
        db.delete_link(link_id)
        monitor._publish({"type": "links", "data": monitor.links()})
        return {"ok": True}

    @app.get("/api/history")
    async def port_history(device: str, port: str, range: str = "day"):
        try:
            return await asyncio.to_thread(history.query, device, port, range)
        except ValueError as e:
            raise HTTPException(400, str(e))

    @app.get("/api/find")
    async def find(q: str):
        return await asyncio.to_thread(inventory.search, q[:100])

    @app.get("/api/inventory/new")
    async def new_devices(hours: int = 24):
        return {"total": inventory.count(), "new": await asyncio.to_thread(inventory.recent_new, min(hours, 24 * 30))}

    @app.get("/api/compliance")
    async def compliance_report():
        return compliance.report(monitor)

    @app.get("/api/report")
    async def report(range: str = "week"):
        try:
            return await asyncio.to_thread(reports.build, monitor, history, range)
        except ValueError as e:
            raise HTTPException(400, str(e))

    @app.post("/api/test-notify")
    async def test_notify(request: Request):
        require_admin(request)
        return await notifier.test()

    @app.post("/api/demo/fail")
    async def demo_fail(request: Request):
        require_admin(request)
        if not sim:
            raise HTTPException(400, "only available in demo mode")
        return sim.fail_random_uplink(60) or {"device": None}

    @app.websocket("/ws")
    async def ws(sock: WebSocket):
        origin = sock.headers.get("origin")
        if origin and urlparse(origin).netloc != sock.headers.get("host"):
            await sock.close(code=4403)          # another website trying to read our live feed
            return
        if cfg.auth.enabled and auth.session(sock.cookies.get(COOKIE)) is None:
            await sock.close(code=4401)
            return
        await sock.accept()
        q = monitor.subscribe()
        try:
            await sock.send_json({"type": "state", "data": monitor.state()})
            while True:
                msg = await q.get()
                await sock.send_json(msg)
        except Exception:  # client went away
            pass
        finally:
            monitor.unsubscribe(q)

    return app
