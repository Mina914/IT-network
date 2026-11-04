"""Web server: REST API + WebSocket live updates + background pollers."""
from __future__ import annotations

import asyncio
import logging
import socket
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .config import Config
from .db import Database
from .monitor import Monitor
from .notify import Notifier

log = logging.getLogger("netmon")
STATIC = Path(__file__).parent / "static"


class Ack(BaseModel):
    by: str = "operator"


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


def create_app(cfg: Config) -> FastAPI:
    db = Database(cfg.db_path)
    notifier = Notifier(cfg.alerts, cfg.dashboard_url)
    monitor = Monitor(cfg, db, notifier)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        background = []
        if cfg.demo:
            from .simulator import Simulator
            sim = Simulator(monitor)
            devices = sim.devices
            backend = sim
            app.state.sim = sim
            background.append(asyncio.create_task(sim.run()))
            log.info("DEMO MODE: simulating %d switches", len(devices))
        else:
            from .snmp import SnmpBackend
            devices = cfg.devices
            backend = SnmpBackend()
        for d in devices:
            monitor.add_device(d)
            try:
                d.resolved_ip = socket.gethostbyname(d.host)
            except OSError:
                d.resolved_ip = d.host

        scheduler = PollScheduler(monitor, backend, cfg.poll_interval)
        scheduler.start(devices)
        app.state.scheduler = scheduler

        syslog_transport = None
        if cfg.syslog_enabled and not cfg.demo:
            from .syslog import start_syslog
            try:
                syslog_transport = await start_syslog(monitor, "0.0.0.0", cfg.syslog_port)
            except OSError as e:
                log.error("could not start syslog on udp/%s: %s", cfg.syslog_port, e)

        async def housekeeping():
            while True:
                await asyncio.sleep(3600)
                db.prune_events(90)
        background.append(asyncio.create_task(housekeeping()))

        yield
        scheduler.stop()
        for t in background:
            t.cancel()
        if syslog_transport:
            syslog_transport.close()

    app = FastAPI(title="NetMon", lifespan=lifespan)
    app.state.monitor = monitor

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

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
    async def poll(name: str):
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
    async def ack(alarm_id: int, body: Ack):
        alarm = monitor.ack(alarm_id, body.by.strip()[:50] or "operator")
        if not alarm:
            raise HTTPException(404, "unknown alarm")
        return alarm

    @app.get("/api/links")
    async def links():
        return monitor.links()

    @app.delete("/api/links/{link_id}")
    async def delete_link(link_id: int):
        db.delete_link(link_id)
        monitor._publish({"type": "links", "data": monitor.links()})
        return {"ok": True}

    @app.post("/api/test-notify")
    async def test_notify():
        return await notifier.test()

    @app.post("/api/demo/fail")
    async def demo_fail():
        sim = getattr(app.state, "sim", None)
        if not sim:
            raise HTTPException(400, "only available in demo mode")
        return sim.fail_random_uplink(60) or {"device": None}

    @app.websocket("/ws")
    async def ws(sock: WebSocket):
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
