"""Demo mode: a fake building (2 core switches + 5 floors x 2 access switches).

Lets you see the dashboard, topology and alarms without touching real
equipment. Ports randomly go up/down and an uplink fails now and then.
"""
from __future__ import annotations

import asyncio
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
        ports = []
        for sp in self.sw[dev.name].values():
            p = sp.p
            if p.oper == "up":
                p.in_octets += int(p.speed * 1e6 / 8 * sp.load * random.uniform(5, 15))
                p.out_octets += int(p.speed * 1e6 / 8 * sp.load * random.uniform(5, 15))
                if random.random() < 0.01:
                    p.in_errors += random.randint(1, 20)
            q = Port(**{k: getattr(p, k) for k in p.__dataclass_fields__})
            q.neighbor = dict(p.neighbor) if (p.neighbor and p.oper == "up") else None
            q.in_bps = q.out_bps = 0.0
            ports.append(q)
        model = "C9500-24Y4C" if dev.role == "core" else "C9300-48P"
        return {
            "sysname": f"{dev.name}.corp.local",
            "sysdescr": f"Cisco IOS Software [Cupertino], Catalyst L3 Switch Software ({model}), Version 17.9.4",
            "uptime": int(time.time() - self.boot),
            "ports": ports,
        }

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
