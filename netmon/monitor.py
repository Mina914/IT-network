"""The monitoring engine.

Keeps the live state of every switch and port, learns the topology from
CDP neighbours, decides when something deserves an alarm, and pushes every
change to the web dashboard.

Data arrives from three places:
  * SNMP polling (full snapshot of a switch every N seconds)
  * syslog %LINK-3-UPDOWN messages (instant, a single port)
  * the demo simulator (same shapes as the two above)
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import asdict, dataclass, field

from .config import Config, Device
from .db import Database

log = logging.getLogger("netmon.monitor")

_ABBR = [
    ("TwentyFiveGigE", "Twe"), ("TenGigabitEthernet", "Te"), ("TwoGigabitEthernet", "Tw"),
    ("FiveGigabitEthernet", "Fi"), ("FortyGigabitEthernet", "Fo"), ("HundredGigE", "Hu"),
    ("AppGigabitEthernet", "Ap"), ("GigabitEthernet", "Gi"), ("FastEthernet", "Fa"),
    ("Port-channel", "Po"), ("Ethernet", "Eth"),
]


def short_ifname(name: str) -> str:
    """GigabitEthernet1/0/5 -> Gi1/0/5 (the form Cisco uses for ifName)."""
    name = name.strip()
    for long, short in _ABBR:
        if name.startswith(long):
            return short + name[len(long):]
    return name


def short_hostname(device_id: str) -> str:
    """CDP device-id 'F1-SW1.corp.local' or 'N9K(FDO123)' -> 'f1-sw1' / 'n9k'."""
    return device_id.split("(")[0].split(".")[0].strip().lower()


@dataclass
class Port:
    ifindex: int
    name: str                 # short name, e.g. Gi1/0/5
    descr: str = ""           # ifDescr, e.g. GigabitEthernet1/0/5
    alias: str = ""           # the 'description' configured on the port
    admin: str = "up"         # up | down
    oper: str = "down"        # up | down | ...
    speed: int = 0            # Mbps
    vlan: int | None = None
    trunk: bool = False
    in_errors: int = 0
    out_errors: int = 0
    in_octets: int = 0
    out_octets: int = 0
    in_bps: float = 0.0
    out_bps: float = 0.0
    last_change: float | None = None
    neighbor: dict | None = None     # {"device", "port", "platform"} from CDP
    util: float | None = None        # % of link speed (max of in/out)
    poe_w: float | None = None       # PoE watts delivered on this port
    patch: dict | None = None        # {"panel", "panel_port", "location"} from the patch panel CSV


@dataclass
class DeviceState:
    cfg: Device
    reachable: bool | None = None
    fail_count: int = 0
    last_poll: float | None = None
    last_error: str = ""
    sysname: str = ""
    sysdescr: str = ""
    uptime: int = 0                  # seconds
    ports: dict[int, Port] = field(default_factory=dict)
    health: dict = field(default_factory=dict)   # cpu, mem_pct, temps, fans, psus
    poe: dict | None = None                      # {"budget_w", "used_w"}
    info: dict = field(default_factory=dict)     # contact, location, ntp

    def port_by_name(self, name: str) -> Port | None:
        name = short_ifname(name)
        for p in self.ports.values():
            if p.name == name or short_ifname(p.descr) == name:
                return p
        return None


def _is_up(oper: str) -> bool:
    return oper == "up"


class Monitor:
    def __init__(self, cfg: Config, db: Database, notifier):
        self.cfg = cfg
        self.db = db
        self.notifier = notifier
        self.devices: dict[str, DeviceState] = {}
        self.active: dict[str, dict] = {a["key"]: a for a in db.active_alarms()}
        self._listeners: set[asyncio.Queue] = set()
        self._critical_re = re.compile(cfg.alerts.critical_description_regex) \
            if cfg.alerts.critical_description_regex else None
        self.poll_request = lambda name: None      # set by the scheduler
        self._tasks: set[asyncio.Task] = set()
        self.history = None                        # history.History
        self.panels = None                         # patchpanels.PatchPanels
        self._over: dict[str, int] = {}            # consecutive polls above a threshold
        self._clean: dict[str, int] = {}           # consecutive clean polls (errors)

    def add_device(self, dev: Device):
        self.devices[dev.name] = DeviceState(cfg=dev)

    # ------------------------------------------------------------------ pub/sub
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=2000)
        self._listeners.add(q)
        return q

    def unsubscribe(self, q):
        self._listeners.discard(q)

    def _publish(self, msg: dict):
        for q in list(self._listeners):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                self._listeners.discard(q)

    def _publish_device(self, dev: DeviceState):
        self._publish({"type": "device", "data": self.device_dict(dev)})
        self._publish({"type": "links", "data": self.links()})

    def _event(self, severity, device, port, message):
        ev = self.db.add_event(severity, device, port, message)
        log.info("[%s] %s %s %s", severity, device, port or "", message)
        self._publish({"type": "event", "data": ev})

    def _spawn(self, coro):
        t = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    # ------------------------------------------------------------------ topology
    def _known_device_for(self, neighbor_id: str) -> str | None:
        want = short_hostname(neighbor_id)
        for d in self.devices.values():
            if want in (d.cfg.name.lower(), short_hostname(d.sysname or "")):
                return d.cfg.name
        return None

    def _link_ports(self) -> set[tuple[str, str]]:
        s = set()
        for l in self.db.links():
            s.add((l["a_device"], l["a_port"]))
            s.add((l["b_device"], l["b_port"]))
        return s

    def links(self) -> list[dict]:
        out = []
        for l in self.db.links():
            ends = []
            for dname, pname in ((l["a_device"], l["a_port"]), (l["b_device"], l["b_port"])):
                d = self.devices.get(dname)
                p = d.port_by_name(pname) if d else None
                ends.append((d, p))
            states = []
            speed = 0
            for d, p in ends:
                if d is not None and d.reachable is False:
                    states.append("down")
                elif p is not None:
                    states.append("up" if _is_up(p.oper) else "down")
                    speed = max(speed, p.speed)
                else:
                    states.append("unknown")
            status = "down" if "down" in states else ("up" if "up" in states else "unknown")
            out.append({**l, "status": status, "speed": speed})
        return out

    def _learn_links(self, dev: DeviceState):
        changed = False
        for p in dev.ports.values():
            if not p.neighbor:
                continue
            other = self._known_device_for(p.neighbor.get("device", ""))
            if other and other != dev.cfg.name:
                if self.db.upsert_link(dev.cfg.name, p.name, other, short_ifname(p.neighbor.get("port", ""))):
                    changed = True
                    self._event("info", dev.cfg.name, p.name,
                                f"New link discovered: {dev.cfg.name} {p.name} <-> {other} {short_ifname(p.neighbor.get('port', ''))}")
        return changed

    # ------------------------------------------------------------------ alarm rules
    def _is_critical(self, dev: DeviceState, p: Port, link_ports=None) -> bool:
        if self.cfg.alerts.alert_on == "all":
            return True
        link_ports = link_ports if link_ports is not None else self._link_ports()
        if (dev.cfg.name, p.name) in link_ports:
            return True
        if p.neighbor and self._known_device_for(p.neighbor.get("device", "")):
            return True
        if self._critical_re and p.alias and self._critical_re.search(p.alias):
            return True
        return False

    def _port_label(self, p: Port) -> str:
        label = f"{p.name} ({p.alias})" if p.alias else p.name
        if p.patch:
            label += f" @ {p.patch['panel']}/{p.patch['panel_port']}"
            if p.patch.get("location"):
                label += f" {p.patch['location']}"
        return label

    def port_label(self, dev, p: Port) -> str:
        return f"{dev.cfg.name} {self._port_label(p)}"

    def _port_changed(self, dev: DeviceState, p: Port, old_oper: str, old_admin: str, source: str):
        name, key = dev.cfg.name, f"{dev.cfg.name}|{p.name}"
        if p.admin != "up" and old_admin == "up":
            self._event("info", name, p.name, f"{self._port_label(p)} administratively shut down")
            self._clear(key, f"{p.name} was shut down by an admin")
            return
        if p.admin != "up":
            return
        if not _is_up(p.oper) and _is_up(old_oper):
            if self._is_critical(dev, p):
                self._event("critical", name, p.name, f"LINK DOWN {self._port_label(p)} [{source}]")
                self._raise(key, name, p.name, "critical", f"Link down: {name} {self._port_label(p)}")
            else:
                self._event("info", name, p.name, f"{self._port_label(p)} went down [{source}]")
        elif _is_up(p.oper) and not _is_up(old_oper):
            if key in self.active:
                self._event("recovery", name, p.name, f"LINK UP {self._port_label(p)} [{source}]")
                self._clear(key, f"{name} {p.name} is back up")
            else:
                self._event("info", name, p.name, f"{self._port_label(p)} came up [{source}]")

    def _raise(self, key, device, port, severity, message):
        if key in self.active:
            return
        alarm = self.db.raise_alarm(key, device, port, severity, message)
        self.active[key] = alarm
        self._publish({"type": "alarm_raised", "data": alarm})
        if severity == "critical" or self.cfg.alerts.notify_warnings:
            self._spawn(self._notify_later(alarm))

    def _clear(self, key, message):
        alarm = self.active.pop(key, None)
        if not alarm:
            return
        alarm = self.db.clear_alarm(alarm["id"])
        self._publish({"type": "alarm_cleared", "data": alarm})
        if alarm["notified"] and self.cfg.alerts.send_recovery:
            self._spawn(self.notifier.send(alarm, self._context(alarm), recovered=True))

    async def _notify_later(self, alarm):
        await asyncio.sleep(self.cfg.alerts.notify_delay_seconds)
        current = self.active.get(alarm["key"])
        if not current or current["id"] != alarm["id"]:
            log.info("alarm %s cleared within %ss, no notification sent", alarm["id"],
                     self.cfg.alerts.notify_delay_seconds)
            return
        current["notified"] = 1
        self.db.mark_notified(alarm["id"])
        await self.notifier.send(current, self._context(current), recovered=False)

    def _context(self, alarm) -> dict:
        d = self.devices.get(alarm["device"])
        ctx = {"Device": alarm["device"]}
        if d:
            ctx["IP"] = d.cfg.host
            ctx["Floor"] = str(d.cfg.floor)
            ctx["Role"] = d.cfg.role
            if alarm["port"]:
                p = d.port_by_name(alarm["port"])
                if p:
                    ctx["Port"] = p.name
                    if p.alias:
                        ctx["Description"] = p.alias
                    if p.neighbor:
                        ctx["Neighbor"] = f"{p.neighbor.get('device')} {p.neighbor.get('port')}"
                    if p.patch:
                        ctx["Patch panel"] = f"{p.patch['panel']} port {p.patch['panel_port']}"
                        if p.patch.get("location"):
                            ctx["Location"] = p.patch["location"]
        ctx["Raised"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(alarm["raised_ts"]))
        if alarm.get("cleared_ts"):
            ctx["Cleared"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(alarm["cleared_ts"]))
            ctx["Duration"] = _fmt_duration(alarm["cleared_ts"] - alarm["raised_ts"])
        return ctx

    def ack(self, alarm_id: int, by: str):
        alarm = self.db.ack_alarm(alarm_id, by)
        if alarm and alarm["key"] in self.active and self.active[alarm["key"]]["id"] == alarm_id:
            self.active[alarm["key"]] = alarm
        if alarm:
            self._publish({"type": "alarm_updated", "data": alarm})
            self._event("info", alarm["device"], alarm["port"], f"Alarm acknowledged by {by}")
        return alarm

    # ------------------------------------------------------------------ inputs
    def apply_snapshot(self, name: str, snap: dict):
        dev = self.devices[name]
        now = time.time()
        first = dev.last_poll is None
        dt = (now - dev.last_poll) if dev.last_poll else 0
        was_down = dev.reachable is False

        dev.reachable = True
        dev.fail_count = 0
        dev.last_error = ""
        dev.sysname = snap.get("sysname", dev.sysname)
        dev.sysdescr = snap.get("sysdescr", dev.sysdescr)
        dev.uptime = snap.get("uptime", dev.uptime)
        if "health" in snap:
            dev.health = snap["health"] or {}
        if "poe" in snap:
            dev.poe = snap["poe"]
        if "info" in snap:
            dev.info = snap["info"] or {}
        poe_ports = (snap.get("poe") or {}).get("ports", {})

        old_ports = dev.ports
        new_ports: dict[int, Port] = {}
        changes = []
        for p in snap["ports"]:
            old = old_ports.get(p.ifindex)
            if old is not None:
                if dt > 0:
                    if p.in_octets >= old.in_octets:
                        p.in_bps = (p.in_octets - old.in_octets) * 8 / dt
                    if p.out_octets >= old.out_octets:
                        p.out_bps = (p.out_octets - old.out_octets) * 8 / dt
                p.last_change = old.last_change
                # a link that just went down has no CDP neighbour any more; keep the old one
                if p.neighbor is None and old.neighbor and not _is_up(p.oper):
                    p.neighbor = old.neighbor
                if old.oper != p.oper or old.admin != p.admin:
                    p.last_change = now
                    changes.append((p, old.oper, old.admin))
                if old.vlan is not None and p.vlan is not None and old.vlan != p.vlan and not p.trunk:
                    self._event("warning", name, p.name, f"VLAN changed {old.vlan} → {p.vlan} on {self._port_label(p)}")
            if p.speed and _is_up(p.oper):
                p.util = round(100 * max(p.in_bps, p.out_bps) / (p.speed * 1e6), 1)
            p.poe_w = poe_ports.get(p.name)
            if self.panels:
                p.patch = self.panels.lookup(name, p.name)
            if self.history is not None and old is not None and dt > 0:
                self.history.add(name, p.name, p.in_bps, p.out_bps, now)
            new_ports[p.ifindex] = p
        dev.ports = new_ports
        dev.last_poll = now

        self._learn_links(dev)
        self._check_health(dev)
        self._check_ports(dev, old_ports)

        if was_down:
            self._event("recovery", name, None, "Device is reachable again")
            self._clear(f"{name}|*", f"{name} is reachable again")

        for p, old_oper, old_admin in changes:
            self._port_changed(dev, p, old_oper, old_admin, source="snmp")

        if first:
            # On start-up, alarm on important links that are already down.
            link_ports = self._link_ports()
            for p in dev.ports.values():
                if p.admin == "up" and not _is_up(p.oper) and self._is_critical(dev, p, link_ports):
                    self._raise(f"{name}|{p.name}", name, p.name, "critical",
                                f"Link down: {name} {self._port_label(p)}")
                    self._event("critical", name, p.name, f"LINK DOWN {self._port_label(p)} (found at start-up)")
            # and clear stale alarms from a previous run that are fine now
            for key, alarm in list(self.active.items()):
                if alarm["device"] == name and alarm["port"] and key == f"{name}|{alarm['port']}":
                    p = dev.port_by_name(alarm["port"])
                    if p is None or _is_up(p.oper) or p.admin != "up":
                        self._clear(key, "resolved while monitor was offline")
        self._publish_device(dev)

    # ------------------------------------------------------------------ health & port checks
    def _threshold(self, key, device, port, over: bool, clear: bool, message: str, polls=2):
        """Raise a warning after `polls` consecutive polls over the limit; clear when `clear`."""
        if over:
            self._over[key] = self._over.get(key, 0) + 1
            if self._over[key] >= polls and key not in self.active:
                self._event("warning", device, port, message)
                self._raise(key, device, port, "warning", message)
        else:
            self._over.pop(key, None)
            if clear and key in self.active:
                self._event("recovery", device, port, f"OK again: {self.active[key]['message']}")
                self._clear(key, "back to normal")

    def _check_health(self, dev: DeviceState):
        t, h, name = self.cfg.thresholds, dev.health or {}, dev.cfg.name
        cpu = h.get("cpu")
        if cpu is not None:
            self._threshold(f"{name}|#cpu", name, None, cpu >= t.cpu_percent, cpu < t.cpu_percent - 10,
                            f"High CPU on {name}: {cpu:.0f}%")
        mem = h.get("mem_pct")
        if mem is not None:
            self._threshold(f"{name}|#mem", name, None, mem >= t.memory_percent, mem < t.memory_percent - 5,
                            f"High memory use on {name}: {mem:.0f}%")
        # environment: Cisco states 1 normal, 2 warning, 3 critical, 4 shutdown, 5 notPresent, 6 notFunctioning
        seen = set()
        for kind, items in (("temp", h.get("temps", [])), ("fan", h.get("fans", [])), ("psu", h.get("psus", []))):
            for it in items:
                key = f"{name}|#{kind}:{it['name']}"
                seen.add(key)
                state = it.get("state", 1)
                bad = state in (2, 3, 4, 6)
                sev = "warning" if state == 2 else "critical"
                what = {"temp": "Temperature", "fan": "Fan", "psu": "Power supply"}[kind]
                val = f" {it['value']}°C" if kind == "temp" and it.get("value") is not None else ""
                text = {2: "WARNING", 3: "CRITICAL", 4: "SHUTDOWN", 6: "NOT WORKING"}.get(state, "")
                if bad and key not in self.active:
                    msg = f"{what} {text} on {name}: {it['name']}{val}"
                    self._event(sev, name, None, msg)
                    self._raise(key, name, None, sev, msg)
                elif not bad and key in self.active:
                    self._event("recovery", name, None, f"{what} OK on {name}: {it['name']}")
                    self._clear(key, "normal")
        for key in [k for k in self.active if k.startswith(f"{name}|#") and k.split("|#")[1].split(":")[0] in
                    ("temp", "fan", "psu") and k not in seen and h]:
            self._clear(key, "sensor gone")
        if dev.poe and dev.poe.get("budget_w"):
            pct = 100 * dev.poe.get("used_w", 0) / dev.poe["budget_w"]
            self._threshold(f"{name}|#poe", name, None, pct >= t.poe_budget_percent, pct < t.poe_budget_percent - 5,
                            f"PoE budget almost used on {name}: {dev.poe.get('used_w', 0):.0f} of "
                            f"{dev.poe['budget_w']:.0f} W ({pct:.0f}%)", polls=1)

    def _check_ports(self, dev: DeviceState, old_ports: dict):
        t, name = self.cfg.thresholds, dev.cfg.name
        link_ports = self._link_ports()
        for p in dev.ports.values():
            watch = self._is_critical(dev, p, link_ports)
            if watch and p.util is not None:
                self._threshold(f"{name}|{p.name}|util", name, p.name, p.util >= t.utilization_percent,
                                p.util < t.utilization_clear_percent,
                                f"High utilisation on {name} {self._port_label(p)}: {p.util:.0f}% of {p.speed // 1000 if p.speed >= 1000 else p.speed}{'G' if p.speed >= 1000 else 'M'}")
            elif f"{name}|{p.name}|util" in self.active and not _is_up(p.oper):
                self._clear(f"{name}|{p.name}|util", "link down")
            old = old_ports.get(p.ifindex)
            if old is None:
                continue
            delta = (p.in_errors - old.in_errors) + (p.out_errors - old.out_errors)
            key = f"{name}|{p.name}|err"
            if delta >= t.errors_per_poll:
                self._clean.pop(key, None)
                if key not in self.active:
                    msg = f"Errors increasing on {name} {self._port_label(p)}: +{delta} since last poll (cable/SFP?)"
                    self._event("warning", name, p.name, msg)
                    self._raise(key, name, p.name, "warning", msg)
            elif key in self.active:
                self._clean[key] = self._clean.get(key, 0) + 1
                if self._clean[key] >= 10:
                    self._clean.pop(key)
                    self._event("recovery", name, p.name, f"No new errors on {name} {p.name}")
                    self._clear(key, "errors stopped")

    def apply_poll_failure(self, name: str, error: str):
        dev = self.devices[name]
        dev.fail_count += 1
        dev.last_error = error
        if dev.fail_count >= self.cfg.fail_threshold and dev.reachable is not False:
            dev.reachable = False
            self._event("critical", name, None, f"Device unreachable: {error}")
            self._raise(f"{name}|*", name, None, "critical",
                        f"Switch unreachable: {name} ({dev.cfg.host})")
            self._publish_device(dev)
        else:
            self._publish({"type": "device", "data": self.device_dict(dev)})

    def apply_port_status(self, name: str, port_name: str, state: str, source: str = "syslog"):
        """Instant update for one port, e.g. from a syslog message.
        state: 'up', 'down' or 'admin_down'."""
        dev = self.devices.get(name)
        if not dev:
            return
        p = dev.port_by_name(port_name)
        if p is None:
            self.poll_request(name)
            return
        old_oper, old_admin = p.oper, p.admin
        if state == "admin_down":
            p.admin, p.oper = "down", "down"
        elif state == "down":
            p.admin, p.oper = "up", "down"
        else:
            p.admin, p.oper = "up", "up"
        if (old_oper, old_admin) != (p.oper, p.admin):
            p.last_change = time.time()
            if not _is_up(p.oper):
                p.in_bps = p.out_bps = 0.0
            self._port_changed(dev, p, old_oper, old_admin, source)
            self._publish_device(dev)
        self.poll_request(name)      # confirm with SNMP straight away

    def find_device_by_ip(self, ip: str) -> str | None:
        for d in self.devices.values():
            if d.cfg.host == ip or getattr(d.cfg, "resolved_ip", None) == ip:
                return d.cfg.name
        return None

    # ------------------------------------------------------------------ views
    def device_status(self, dev: DeviceState) -> str:
        if dev.reachable is False:
            return "down"
        if dev.reachable is None:
            return "unknown"
        if any(a["device"] == dev.cfg.name for a in self.active.values()):
            return "warning"
        return "up"

    def device_dict(self, dev: DeviceState) -> dict:
        ports = sorted(dev.ports.values(), key=lambda p: p.ifindex)
        return {
            "name": dev.cfg.name,
            "host": dev.cfg.host,
            "role": dev.cfg.role,
            "floor": dev.cfg.floor,
            "status": self.device_status(dev),
            "reachable": dev.reachable,
            "last_poll": dev.last_poll,
            "last_error": dev.last_error,
            "sysname": dev.sysname,
            "sysdescr": dev.sysdescr,
            "uptime": dev.uptime,
            "ports_up": sum(1 for p in ports if _is_up(p.oper)),
            "ports_total": len(ports),
            "health": dev.health,
            "poe": dev.poe,
            "info": dev.info,
            "ports": [asdict(p) for p in ports],
        }

    def state(self) -> dict:
        return {
            "devices": [self.device_dict(d) for d in self.devices.values()],
            "links": self.links(),
            "alarms": sorted(self.active.values(), key=lambda a: -a["raised_ts"]),
            "events": self.db.recent_events(150),
            "panels": self.panels.to_list() if self.panels else [],
            "thresholds": vars(self.cfg.thresholds),
            "demo": self.cfg.demo,
        }


def _fmt_duration(sec: float) -> str:
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m}m {s}s" if h else (f"{m}m {s}s" if m else f"{s}s")
