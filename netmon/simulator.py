"""Demo mode: a fake building (2 core switches + 5 floors x 2 access switches).

Lets you see the dashboard, topology and alarms without touching real
equipment. Ports randomly go up/down and an uplink fails now and then.
"""
from __future__ import annotations

import asyncio
import math
import random
import time

from .config import Device
from .monitor import Port

FLOORS = 5
ROOMS = ["Office", "Meeting Room", "Reception", "HR", "Finance", "IT", "Sales", "Manager"]


def build_devices() -> list[Device]:
    devs = [Device("CORE-SW1", "10.10.0.1", "core", 0), Device("CORE-SW2", "10.10.0.2", "core", 0)]
    for f in range(1, FLOORS + 1):
        for s in (1, 2):
            devs.append(Device(f"F{f}-SW{s}", f"10.10.{f}.{10 + s}", "access", f))
    return devs


class SimPort:
    def __init__(self, ifindex, name, descr, alias, speed, vlan=None, trunk=False, neighbor=None, up=True):
        self.p = Port(ifindex=ifindex, name=name, descr=descr, alias=alias, speed=speed,
                      vlan=vlan, trunk=trunk, oper="up" if up else "down", neighbor=neighbor)
        self.load = random.uniform(0.001, 0.05) if up else 0
        self.fixed_down_until = 0.0


class Simulator:
    def __init__(self, monitor):
        self.monitor = monitor
        self.devices = build_devices()
        self.sw: dict[str, dict[str, SimPort]] = {}
        self.unreachable_until: dict[str, float] = {}
        self.boot = time.time() - random.randint(5, 90) * 86400
        self._build()
        self._extras()

    def _build(self):
        access = [d for d in self.devices if d.role == "access"]
        for core_i, core in enumerate(("CORE-SW1", "CORE-SW2"), start=1):
            ports = {}
            for n in range(1, 25):
                name = f"Te1/0/{n}"
                alias, nb, up = "", None, False
                if n <= len(access):
                    a = access[n - 1]
                    alias = f"DOWNLINK {a.name} Te1/1/{core_i}"
                    nb = {"device": f"{a.name}.corp.local", "port": f"TenGigabitEthernet1/1/{core_i}",
                          "platform": "cisco C9300-48P"}
                    up = True
                elif n == 23:
                    alias, up = "FIREWALL FW-01 inside", True
                elif n == 24:
                    other = "CORE-SW2" if core == "CORE-SW1" else "CORE-SW1"
                    alias, up = f"CORE-LINK to {other}", True
                    nb = {"device": f"{other}.corp.local", "port": "TenGigabitEthernet1/0/24",
                          "platform": "cisco C9500-24Y4C"}
                ports[name] = SimPort(n, name, f"TenGigabitEthernet1/0/{n}", alias, 10000,
                                      trunk=bool(alias), neighbor=nb, up=up)
            for n in range(1, 5):
                name = f"Gi1/0/{n}"
                alias = {1: "SERVER ESXi-01", 2: "SERVER ESXi-02", 3: "WLC-01"}.get(n, "")
                ports[name] = SimPort(100 + n, name, f"GigabitEthernet1/0/{n}", alias, 1000,
                                      vlan=100, up=bool(alias))
            self.sw[core] = ports

        for a in access:
            ports = {}
            f = a.floor
            for n in range(1, 49):
                name = f"Gi1/0/{n}"
                r = random.random()
                if n in (47, 48):
                    alias, vlan, up = f"AP-F{f}-{a.name[-1]}{n - 46}", 50, True
                elif n == 46:
                    alias, vlan, up = f"PRINTER F{f}", 30, True
                elif r < 0.75:
                    alias = f"F{f} {random.choice(ROOMS)} PC-{a.name[-1]}{n:02d}"
                    vlan, up = 10, random.random() < 0.8
                elif r < 0.85:
                    alias, vlan, up = f"F{f} IP-PHONE {n:02d}", 20, True
                else:
                    alias, vlan, up = "", 999, False
                ports[name] = SimPort(n, name, f"GigabitEthernet1/0/{n}", alias, 1000, vlan=vlan, up=up)
            for u in (1, 2):
                core = f"CORE-SW{u}"
                core_port = [p for p in self.sw[core].values() if p.p.alias.startswith(f"DOWNLINK {a.name} ")][0]
                name = f"Te1/1/{u}"
                ports[name] = SimPort(
                    60 + u, name, f"TenGigabitEthernet1/1/{u}", f"UPLINK to {core} {core_port.p.name}", 10000,
                    trunk=True, up=True,
                    neighbor={"device": f"{core}.corp.local", "port": core_port.p.descr,
                              "platform": "cisco C9500-24Y4C"})
            self.sw[a.name] = ports

    # ------------------------------------------------------------------ backend API
    async def poll(self, dev: Device) -> dict:
        await asyncio.sleep(random.uniform(0.05, 0.3))
        if time.time() < self.unreachable_until.get(dev.name, 0):
            raise TimeoutError("No SNMP response received before timeout")
        now = time.time()
        dt = max(1.0, now - self.last_poll.get(dev.name, now - 15))
        self.last_poll[dev.name] = now
        ports = []
        for sp in self.sw[dev.name].values():
            p = sp.p
            if p.oper == "up":
                busy = now < sp.busy_until
                frac = random.uniform(0.86, 0.97) if busy else sp.load * random.uniform(0.6, 1.4)
                p.in_octets += int(p.speed * 1e6 / 8 * dt * frac)
                p.out_octets += int(p.speed * 1e6 / 8 * dt * frac * random.uniform(0.5, 1.0))
                if random.random() < 0.01:
                    p.in_errors += random.randint(1, 20)
            q = Port(**{k: getattr(p, k) for k in p.__dataclass_fields__})
            q.neighbor = dict(p.neighbor) if (p.neighbor and p.oper == "up") else None
            q.in_bps = q.out_bps = 0.0
            ports.append(q)
        model = "C9500-24Y4C" if dev.role == "core" else "C9300-48P"
        x = self.extra[dev.name]
        return {
            "sysname": f"{dev.name}.corp.local",
            "sysdescr": f"Cisco IOS Software [Cupertino], Catalyst L3 Switch Software ({model}), Version {x['version']}",
            "uptime": int(now - x["boot"]),
            "ports": ports,
            "health": self._health(dev.name, now),
            "poe": self._poe(dev.name),
            "info": x["info"],
        }

    async def poll_fdb(self, dev: Device) -> dict:
        await asyncio.sleep(random.uniform(0.05, 0.2))
        if time.time() < self.unreachable_until.get(dev.name, 0):
            raise TimeoutError("No SNMP response received before timeout")
        macs = [(m["mac"], self.sw[dev.name][pn].p.vlan, self.sw[dev.name][pn].p.ifindex)
                for (dn, pn), m in self.macs.items() if dn == dev.name and self.sw[dn][pn].p.oper == "up"]
        arp = [(m["ip"], m["mac"]) for m in self.macs.values()] if dev.role == "core" else []
        return {"macs": macs, "arp": arp}

    # ------------------------------------------------------------------ extras (health, PoE, MACs, panels)
    def _extras(self):
        self.last_poll: dict[str, float] = {}
        self.extra: dict[str, dict] = {}
        self.macs: dict[tuple[str, str], dict] = {}
        for d in self.devices:
            info = {"contact": "it-network@corp.local",
                    "location": "HQ Server room, rack R1" if d.role == "core" else f"HQ Floor {d.floor}, IDF-{d.floor}",
                    "ntp": 6}
            if d.name == "F5-SW2":
                info["contact"] = ""
            if d.name == "F3-SW1":
                info["location"] = ""
            if d.name == "F4-SW1":
                info["ntp"] = 3
            core = d.role == "core"
            self.extra[d.name] = {
                "info": info,
                "version": "17.6.5" if d.name == "F5-SW1" else "17.9.4",
                "boot": time.time() - (400 * 86400 if d.name == "CORE-SW2" else random.randint(20, 200) * 86400),
                "cpu": random.uniform(6, 18) if core else random.uniform(3, 12),
                "mem": random.uniform(35, 55),
                "temp": random.uniform(27, 34),
                "fans": ["FAN 1", "FAN 2", "FAN 3"] if core else ["FAN 1", "FAN 2"],
                "psus": ["PS1", "PS2"] if core else ["PS1"],
                "bad": {},                       # sensor name -> (state, until)
                "cpu_spike_until": 0,
                "poe_budget": None if core else (270.0 if d.name == "F2-SW1" else 437.0),
            }
            for sp in self.sw[d.name].values():
                p = sp.p
                if d.role == "access" and p.name.startswith("Gi") and not p.alias:
                    if random.random() < 0.5:
                        p.admin = "down"                 # some unused ports are shut down, some not
                if p.name.startswith("Gi") and p.alias and not p.trunk:
                    self.macs[(d.name, p.name)] = self._new_mac(d, p)
            if d.name == "F2-SW1":
                for n in range(30, 46):
                    sp = self.sw[d.name][f"Gi1/0/{n}"]
                    sp.p.alias, sp.p.vlan, sp.p.oper, sp.p.admin = f"CAMERA F2-{n:02d}", 40, "up", "up"
                    sp.load = random.uniform(0.004, 0.008)
                    self.macs[(d.name, sp.p.name)] = self._new_mac(d, sp.p)
            if d.name == "F2-SW2":
                sp = self.sw[d.name]["Gi1/0/44"]
                sp.p.alias, sp.p.vlan, sp.p.oper, sp.p.admin = "F2 Meeting Room TV", 1, "up", "up"
            for sp in self.sw[d.name].values():
                sp.busy_until = 0.0

    def _new_mac(self, d, p):
        mac = "00:1b:%02x:%02x:%02x:%02x" % tuple(random.randrange(256) for _ in range(4))
        floor = d.floor or 0
        vlan = p.vlan or 100
        return {"mac": mac, "ip": f"10.{floor}{vlan // 10 % 10}.{vlan}.{random.randint(10, 250)}"}

    def _health(self, name, now):
        x = self.extra[name]
        x["bad"] = {k: v for k, v in x["bad"].items() if v[1] > now}
        cpu = random.uniform(85, 97) if now < x["cpu_spike_until"] else max(1.0, x["cpu"] + random.uniform(-3, 3))
        temp_bad = x["bad"].get("Inlet Temp Sensor")
        temps = [{"name": "Inlet Temp Sensor", "value": int(temp_bad[2] if temp_bad else x["temp"] + random.uniform(-1, 1)),
                  "state": temp_bad[0] if temp_bad else 1},
                 {"name": "Hotspot Temp Sensor", "value": int(x["temp"] + 12 + random.uniform(-1, 1)), "state": 1}]
        fans = [{"name": f, "state": x["bad"].get(f, (1,))[0]} for f in x["fans"]]
        psus = [{"name": ps, "state": x["bad"].get(ps, (1,))[0]} for ps in x["psus"]]
        return {"cpu": round(cpu, 1), "mem_pct": round(x["mem"] + random.uniform(-1, 1), 1),
                "temps": temps, "fans": fans, "psus": psus}

    def _poe(self, name):
        x = self.extra[name]
        if not x["poe_budget"]:
            return None
        ports = {}
        for sp in self.sw[name].values():
            a = sp.p.alias
            if sp.p.oper != "up" or not a:
                continue
            if a.startswith("AP-"):
                ports[sp.p.name] = round(random.uniform(15.5, 21.0), 1)
            elif "PHONE" in a:
                ports[sp.p.name] = round(random.uniform(4.5, 6.5), 1)
            elif a.startswith("CAMERA"):
                ports[sp.p.name] = round(random.uniform(12.0, 12.95), 1)
        return {"budget_w": x["poe_budget"], "used_w": round(sum(ports.values()), 1), "ports": ports}

    def patch_rows(self) -> list[dict]:
        rows = []
        for d in self.devices:
            if d.role == "access":
                panel = f"PP-F{d.floor}-{'A' if d.name.endswith('1') else 'B'}"
                for n in range(1, 49):
                    sp = self.sw[d.name][f"Gi1/0/{n}"]
                    a = sp.p.alias
                    loc = (f"Ceiling AP {d.floor}-{n - 46}" if a.startswith("AP-") else
                           f"Print corner F{d.floor}" if a.startswith("PRINTER") else
                           f"Camera point F{d.floor}-{n:02d}" if a.startswith("CAMERA") else
                           f"Room {d.floor}{n:02d}" if d.name.endswith("1") else f"Room {d.floor}{n + 50}")
                    rows.append({"panel": panel, "panel_port": n, "switch": d.name,
                                 "switch_port": f"Gi1/0/{n}", "location": loc})
            elif d.name == "CORE-SW1":
                for n in range(1, 5):
                    rows.append({"panel": "PP-CORE-A", "panel_port": n, "switch": d.name,
                                 "switch_port": f"Gi1/0/{n}", "location": f"Server rack R1 U{10 + n * 2}"})
        return rows

    def backfill_history(self, history):
        """Fill a month of believable traffic so the graphs aren't empty in the demo."""
        if history.db.query("SELECT 1 FROM traffic LIMIT 1"):
            return
        now = time.time()
        rows = []
        for d in self.devices:
            for sp in self.sw[d.name].values():
                p = sp.p
                if p.oper != "up" or not p.speed:
                    continue
                base = p.speed * 1e6 * max(sp.load, 0.004) * (6 if p.trunk else 1)

                def rate(ts):
                    lt = time.localtime(ts)
                    work = 0.15 + 0.85 * max(0.0, math.sin(math.pi * (lt.tm_hour + lt.tm_min / 60 - 7) / 11))
                    if lt.tm_wday >= 5:
                        work *= 0.25
                    return min(p.speed * 1e6 * 0.9, base * work * random.uniform(0.7, 1.3))

                for k in range(1, 289):
                    ts = int((now - k * 300) // 300 * 300)
                    r = rate(ts)
                    rows.append((d.name, p.name, 300, ts, r, r * 0.6, r * 1.6, r * 1.1))
                for k in range(25, 30 * 24):
                    ts = int((now - k * 3600) // 3600 * 3600)
                    r = rate(ts)
                    rows.append((d.name, p.name, 3600, ts, r, r * 0.6, r * 2.2, r * 1.5))
        history.db.executemany(
            "INSERT OR IGNORE INTO traffic(device, port, res, ts, in_avg, out_avg, in_max, out_max) "
            "VALUES (?,?,?,?,?,?,?,?)", rows)

    # ------------------------------------------------------------------ chaos
    def _set(self, dev: str, port: str, up: bool):
        sp = self.sw[dev][port]
        new = "up" if up else "down"
        if sp.p.oper == new:
            return
        sp.p.oper = new
        sp.load = random.uniform(0.001, 0.05) if up else 0
        # a real switch sends a syslog message instantly; emulate that
        self.monitor.apply_port_status(dev, port, "up" if up else "down", source="syslog")

    def _peer(self, dev, port):
        nb = self.sw[dev][port].p.neighbor
        if not nb:
            return None
        other = nb["device"].split(".")[0]
        for sp in self.sw.get(other, {}).values():
            if sp.p.descr == nb["port"]:
                return other, sp.p.name
        return None

    def fail_random_uplink(self, seconds=60):
        """Used by the 'Simulate failure' button in demo mode."""
        choices = [(d.name, u) for d in self.devices if d.role == "access" for u in ("Te1/1/1", "Te1/1/2")
                   if self.sw[d.name][u].p.oper == "up"]
        if not choices:
            return None
        dev, port = random.choice(choices)
        until = time.time() + seconds
        self.sw[dev][port].fixed_down_until = until
        self._set(dev, port, False)
        peer = self._peer(dev, port)
        if peer:
            self.sw[peer[0]][peer[1]].fixed_down_until = until
            self._set(*peer, False)
        return {"device": dev, "port": port, "seconds": seconds}

    async def run(self):
        await asyncio.sleep(20)
        while True:
            await asyncio.sleep(5)
            now = time.time()
            # restore failed uplinks
            for dev, ports in self.sw.items():
                for name, sp in ports.items():
                    if sp.fixed_down_until and now > sp.fixed_down_until:
                        sp.fixed_down_until = 0
                        self._set(dev, name, True)
                        peer = self._peer(dev, name)
                        if peer:
                            self._set(*peer, True)
            # users plugging / unplugging PCs
            for _ in range(random.randint(0, 2)):
                dev = random.choice([d.name for d in self.devices if d.role == "access"])
                port = f"Gi1/0/{random.randint(1, 45)}"
                sp = self.sw[dev][port]
                if sp.p.alias:
                    self._set(dev, port, sp.p.oper != "up")
            # an uplink (fibre) failure every few minutes
            if random.random() < 0.03:
                dev = random.choice([d.name for d in self.devices if d.role == "access"])
                port = random.choice(["Te1/1/1", "Te1/1/2"])
                sp = self.sw[dev][port]
                if sp.p.oper == "up":
                    sp.fixed_down_until = now + random.randint(40, 150)
                    self._set(dev, port, False)
                    peer = self._peer(dev, port)
                    if peer:
                        self._set(*peer, False)
            # a busy uplink, a CPU spike, a hot switch, a failed fan or PSU, a new device, a VLAN change
            if random.random() < 0.02:
                dev = random.choice([d.name for d in self.devices if d.role == "access"])
                self.sw[dev][random.choice(["Te1/1/1", "Te1/1/2"])].busy_until = now + random.randint(60, 150)
            if random.random() < 0.01:
                self.extra["CORE-SW1"]["cpu_spike_until"] = now + random.randint(60, 120)
            if random.random() < 0.006:
                dev = random.choice([d.name for d in self.devices])
                self.extra[dev]["bad"]["Inlet Temp Sensor"] = (2, now + 120, random.randint(52, 58))
            if random.random() < 0.004:
                x = self.extra[random.choice(["CORE-SW1", "CORE-SW2"])]
                x["bad"][random.choice(x["psus"] + x["fans"])] = (6, now + 150)
            if random.random() < 0.02:
                cand = [k for k in self.macs if self.sw[k[0]][k[1]].p.oper == "up" and "PC" in self.sw[k[0]][k[1]].p.alias]
                if cand:
                    k = random.choice(cand)
                    d = next(x for x in self.devices if x.name == k[0])
                    self.macs[k] = self._new_mac(d, self.sw[k[0]][k[1]].p)
            if random.random() < 0.006:
                dev = random.choice([d.name for d in self.devices if d.role == "access"])
                sp = self.sw[dev][f"Gi1/0/{random.randint(1, 40)}"]
                if sp.p.alias and sp.p.vlan in (10, 20):
                    sp.p.vlan = 20 if sp.p.vlan == 10 else 10
            if random.random() < 0.01:
                dev = random.choice([d.name for d in self.devices if d.role == "access"])
                self.sw[dev][random.choice(["Te1/1/1", "Te1/1/2"])].p.in_errors += random.randint(200, 800)
            # very rarely a whole switch stops answering (power cut on a floor)
            if random.random() < 0.004:
                dev = random.choice([d.name for d in self.devices if d.role == "access"])
                if now > self.unreachable_until.get(dev, 0):
                    self.unreachable_until[dev] = now + 120
                    for up in ("Te1/1/1", "Te1/1/2"):
                        peer = self._peer(dev, up)
                        if peer:
                            self.sw[peer[0]][peer[1]].fixed_down_until = now + 120
                            self._set(*peer, False)
