"""SNMPv3 poller for Cisco switches (IF-MIB, CISCO-VLAN-MEMBERSHIP, VTP, CDP).

Security:
  * READ-ONLY: only GET and GETBULK/walk are used. SET is never imported
    (tests/test_credentials.py checks this file for it).
  * authPriv only: every request is authenticated AND encrypted. There is no
    code path for noAuthNoPriv or authNoPriv.
  * Keys come from Device.cred (loaded at runtime by netmon.credentials) and are
    revealed only when building the USM user; they are never logged.
"""
from __future__ import annotations

import logging

from pysnmp.hlapi.v3arch.asyncio import (
    ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget, UsmUserData,
    bulk_walk_cmd, get_cmd,
    usm3DESEDEPrivProtocol, usmAesCfb128Protocol, usmAesCfb192Protocol, usmAesCfb256Protocol,
    usmDESPrivProtocol, usmHMAC128SHA224AuthProtocol, usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol, usmHMAC384SHA512AuthProtocol, usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
)

import re

from .config import Device
from .inventory import mac_from_bytes
from .monitor import Port, short_ifname

log = logging.getLogger("netmon.snmp")

AUTH = {
    "MD5": usmHMACMD5AuthProtocol, "SHA": usmHMACSHAAuthProtocol,
    "SHA1": usmHMACSHAAuthProtocol, "SHA224": usmHMAC128SHA224AuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol, "SHA384": usmHMAC256SHA384AuthProtocol,
    "SHA512": usmHMAC384SHA512AuthProtocol,
}
# AES192/AES256 use the Cisco-compatible key extension.
PRIV = {
    "DES": usmDESPrivProtocol, "3DES": usm3DESEDEPrivProtocol,
    "AES": usmAesCfb128Protocol, "AES128": usmAesCfb128Protocol,
    "AES192": usmAesCfb192Protocol, "AES256": usmAesCfb256Protocol,
}

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"

COLUMNS = {
    "descr":      "1.3.6.1.2.1.2.2.1.2",
    "type":       "1.3.6.1.2.1.2.2.1.3",
    "admin":      "1.3.6.1.2.1.2.2.1.7",
    "oper":       "1.3.6.1.2.1.2.2.1.8",
    "in_errors":  "1.3.6.1.2.1.2.2.1.14",
    "out_errors": "1.3.6.1.2.1.2.2.1.20",
    "name":       "1.3.6.1.2.1.31.1.1.1.1",
    "in_octets":  "1.3.6.1.2.1.31.1.1.1.6",
    "out_octets": "1.3.6.1.2.1.31.1.1.1.10",
    "speed":      "1.3.6.1.2.1.31.1.1.1.15",
    "alias":      "1.3.6.1.2.1.31.1.1.1.18",
    "vlan":       "1.3.6.1.4.1.9.9.68.1.2.2.1.2",     # vmVlan
    "trunk":      "1.3.6.1.4.1.9.9.46.1.6.1.1.14",    # vlanTrunkPortDynamicStatus
}
CDP = {
    "device":   "1.3.6.1.4.1.9.9.23.1.2.1.1.6",
    "port":     "1.3.6.1.4.1.9.9.23.1.2.1.1.7",
    "platform": "1.3.6.1.4.1.9.9.23.1.2.1.1.8",
}
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
NTP_STATUS = "1.3.6.1.4.1.9.9.168.1.1.11.0"          # CISCO-NTP-MIB cntpSysSrvStatus

HEALTH = {
    "cpu":        "1.3.6.1.4.1.9.9.109.1.1.1.1.7",     # cpmCPUTotal1minRev (%)
    "mem_used":   "1.3.6.1.4.1.9.9.109.1.1.1.1.12",    # cpmCPUMemoryUsed (KB)
    "mem_free":   "1.3.6.1.4.1.9.9.109.1.1.1.1.13",    # cpmCPUMemoryFree (KB)
    "temp_descr": "1.3.6.1.4.1.9.9.13.1.3.1.2",        # CISCO-ENVMON-MIB
    "temp_value": "1.3.6.1.4.1.9.9.13.1.3.1.3",
    "temp_state": "1.3.6.1.4.1.9.9.13.1.3.1.6",
    "fan_descr":  "1.3.6.1.4.1.9.9.13.1.4.1.2",
    "fan_state":  "1.3.6.1.4.1.9.9.13.1.4.1.3",
    "psu_descr":  "1.3.6.1.4.1.9.9.13.1.5.1.2",
    "psu_state":  "1.3.6.1.4.1.9.9.13.1.5.1.3",
}
POE = {
    "budget":     "1.3.6.1.2.1.105.1.3.1.1.2",         # pethMainPsePower (W), per stack member
    "used":       "1.3.6.1.2.1.105.1.3.1.1.4",         # pethMainPseConsumptionPower (W)
    "port_mw":    "1.3.6.1.4.1.9.9.402.1.2.1.9",       # cpeExtPsePortPwrConsumption (mW)
}
FDB = {
    "vlans":      "1.3.6.1.4.1.9.9.46.1.3.1.1.2",      # vtpVlanState (index 1.<vlan>)
    "fdb_port":   "1.3.6.1.2.1.17.4.3.1.2",            # dot1dTpFdbPort (per-VLAN context)
    "fdb_status": "1.3.6.1.2.1.17.4.3.1.3",            # 3 = learned
    "bridge_if":  "1.3.6.1.2.1.17.1.4.1.2",            # dot1dBasePortIfIndex
    "qfdb_port":  "1.3.6.1.2.1.17.7.1.2.2.1.2",        # Q-BRIDGE fallback (no context)
    "arp":        "1.3.6.1.2.1.4.22.1.2",              # ipNetToMediaPhysAddress
}

# ethernetCsmacd, ieee8023adLag (port-channel). Add 53 to include SVIs (Vlan interfaces).
IF_TYPES = {6, 161}
OPER = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}
ADMIN = {1: "up", 2: "down", 3: "testing"}


class SnmpError(Exception):
    pass


def _text(v) -> str:
    try:
        return bytes(v).decode("utf-8", "replace").strip("\x00 ").strip()
    except Exception:
        return v.prettyPrint()


class SnmpBackend:
    def __init__(self):
        self._engines: dict[str, SnmpEngine] = {}

    def _engine(self, dev: Device) -> SnmpEngine:
        # one engine per device so different SNMPv3 keys never clash
        if dev.name not in self._engines:
            self._engines[dev.name] = SnmpEngine()
        return self._engines[dev.name]

    def _auth(self, dev: Device) -> UsmUserData:
        c = dev.cred
        if c is None:
            raise SnmpError("no SNMPv3 credential loaded for this device")
        try:
            auth = AUTH[c.auth_protocol.upper()]
            priv = PRIV[c.priv_protocol.upper()]
        except KeyError as e:
            raise SnmpError(f"unsupported SNMPv3 protocol {e}") from None
        if not c.auth_key or not c.priv_key:
            raise SnmpError("authPriv requires both an auth key and a privacy key")
        return UsmUserData(
            c.user,
            authKey=c.auth_key.reveal(), privKey=c.priv_key.reveal(),
            authProtocol=auth, privProtocol=priv,
        )

    async def _target(self, dev: Device):
        return await UdpTransportTarget.create(
            (dev.host, dev.snmp.port), timeout=dev.snmp.timeout, retries=dev.snmp.retries)

    async def _get(self, dev, target, *oids):
        err, status, idx, vbs = await get_cmd(
            self._engine(dev), self._auth(dev), target, ContextData(),
            *[ObjectType(ObjectIdentity(o)) for o in oids])
        if err:
            raise SnmpError(str(err))
        if status:
            raise SnmpError(status.prettyPrint())
        return [v for _, v in vbs]

    async def _get_optional(self, dev, target, *oids) -> list:
        """GET that returns None for objects the switch doesn't support."""
        try:
            vals = await self._get(dev, target, *oids)
        except SnmpError:
            return [None] * len(oids)
        return [None if v.__class__.__name__ in ("NoSuchObject", "NoSuchInstance", "EndOfMibView") else v
                for v in vals]

    async def _walk(self, dev, target, oid, context: str = "") -> dict[tuple, object]:
        """Walk one column; returns {index_tuple: value}."""
        base = tuple(int(x) for x in oid.split("."))
        out = {}
        async for err, status, idx, vbs in bulk_walk_cmd(
                self._engine(dev), self._auth(dev), target, ContextData(contextName=context), 0, 30,
                ObjectType(ObjectIdentity(oid)), lexicographicMode=False):
            if err:
                raise SnmpError(str(err))
            if status:      # e.g. noSuchName: the MIB is not supported -> empty column
                break
            for name, val in vbs:
                o = tuple(name)
                if o[:len(base)] != base:
                    continue
                if val.__class__.__name__ in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
                    continue
                out[o[len(base):]] = val
        return out

    def _reset(self, dev: Device):
        """Forget cached SNMPv3 engine state (boots/time) for this device.
        Needed after a switch reboots, otherwise every request keeps failing."""
        eng = self._engines.pop(dev.name, None)
        if eng is not None:
            try:
                eng.close_dispatcher()
            except Exception:
                pass

    async def poll(self, dev: Device) -> dict:
        try:
            return await self._poll(dev)
        except BaseException:
            self._reset(dev)
            raise

    async def _poll(self, dev: Device) -> dict:
        target = await self._target(dev)
        sysdescr, uptime, sysname = await self._get(dev, target, SYS_DESCR, SYS_UPTIME, SYS_NAME)

        cols = {k: await self._walk(dev, target, oid) for k, oid in COLUMNS.items()}
        cdp = {k: await self._walk(dev, target, oid) for k, oid in CDP.items()}

        neighbors: dict[int, dict] = {}
        for idx, val in cdp["device"].items():
            ifindex = idx[0]
            neighbors[ifindex] = {
                "device": _text(val),
                "port": _text(cdp["port"].get(idx, "")) if idx in cdp["port"] else "",
                "platform": _text(cdp["platform"][idx]) if idx in cdp["platform"] else "",
            }

        ports = []
        for idx, t in cols["type"].items():
            if int(t) not in IF_TYPES:
                continue
            i = idx[0]

            def g(col, default=None, conv=int):
                v = cols[col].get(idx)
                return default if v is None else conv(v)

            descr = g("descr", "", _text)
            ports.append(Port(
                ifindex=i,
                name=g("name", "", _text) or short_ifname(descr),
                descr=descr,
                alias=g("alias", "", _text),
                admin=ADMIN.get(g("admin", 2), "down"),
                oper=OPER.get(g("oper", 2), "down"),
                speed=g("speed", 0),
                vlan=g("vlan"),
                trunk=g("trunk", 2) == 1,
                in_errors=g("in_errors", 0),
                out_errors=g("out_errors", 0),
                in_octets=g("in_octets", 0),
                out_octets=g("out_octets", 0),
                neighbor=neighbors.get(i),
            ))
        contact, location, ntp = await self._get_optional(dev, target, SYS_CONTACT, SYS_LOCATION, NTP_STATUS)
        return {
            "sysname": _text(sysname),
            "sysdescr": _text(sysdescr).splitlines()[0][:200],
            "uptime": int(uptime) // 100,
            "ports": ports,
            "health": await self._health(dev, target),
            "poe": await self._poe(dev, target, ports),
            "info": {"contact": _text(contact) if contact is not None else "",
                     "location": _text(location) if location is not None else "",
                     "ntp": int(ntp) if ntp is not None else None},
        }

    async def _health(self, dev, target) -> dict:
        w = {k: await self._walk(dev, target, oid) for k, oid in HEALTH.items()}
        h: dict = {}
        if w["cpu"]:
            h["cpu"] = max(int(v) for v in w["cpu"].values())
        if w["mem_used"] and w["mem_free"]:
            used = sum(int(v) for v in w["mem_used"].values())
            free = sum(int(v) for v in w["mem_free"].values())
            if used + free:
                h["mem_pct"] = round(100 * used / (used + free), 1)
        h["temps"] = [{"name": _text(w["temp_descr"].get(i, "")) or f"sensor {i[0]}",
                       "value": int(w["temp_value"][i]) if i in w["temp_value"] else None,
                       "state": int(st)} for i, st in w["temp_state"].items() if int(st) != 5]
        h["fans"] = [{"name": _text(w["fan_descr"].get(i, "")) or f"fan {i[0]}", "state": int(st)}
                     for i, st in w["fan_state"].items() if int(st) != 5]
        h["psus"] = [{"name": _text(w["psu_descr"].get(i, "")) or f"PSU {i[0]}", "state": int(st)}
                     for i, st in w["psu_state"].items() if int(st) != 5]
        return h

    async def _poe(self, dev, target, ports) -> dict | None:
        budget = await self._walk(dev, target, POE["budget"])
        if not budget:
            return None
        used = await self._walk(dev, target, POE["used"])
        per_port = await self._walk(dev, target, POE["port_mw"])
        # (stack member, port number) -> interface name ending in "<member>/0/<port>"
        by_suffix = {}
        for p in ports:
            m = re.match(r"^[A-Za-z]+(\d+)/0/(\d+)$", p.name)
            if m:
                by_suffix[(int(m.group(1)), int(m.group(2)))] = p.name
        port_w = {}
        for idx, mw in per_port.items():
            if len(idx) >= 2 and int(mw) > 0 and (idx[0], idx[1]) in by_suffix:
                port_w[by_suffix[(idx[0], idx[1])]] = round(int(mw) / 1000, 1)
        return {"budget_w": float(sum(int(v) for v in budget.values())),
                "used_w": float(sum(int(v) for v in used.values())),
                "ports": port_w}

    async def poll_fdb(self, dev: Device) -> dict:
        """MAC address table (per VLAN, Cisco community/context indexing) and ARP table."""
        try:
            return await self._poll_fdb(dev)
        except BaseException:
            self._reset(dev)
            raise

    async def _poll_fdb(self, dev: Device) -> dict:
        target = await self._target(dev)
        macs: list[tuple[str, int | None, int]] = []
        vlans = [idx[-1] for idx, st in (await self._walk(dev, target, FDB["vlans"])).items()
                 if int(st) == 1 and not 1002 <= idx[-1] <= 1005]
        for vlan in vlans:
            ctx = f"vlan-{vlan}"
            fdb = await self._walk(dev, target, FDB["fdb_port"], ctx)
            if not fdb:
                continue
            status = await self._walk(dev, target, FDB["fdb_status"], ctx)
            bridge = await self._walk(dev, target, FDB["bridge_if"], ctx)
            for idx, bport in fdb.items():
                if len(idx) != 6 or int(status.get(idx, 3)) != 3:
                    continue
                ifindex = bridge.get((int(bport),))
                if ifindex is not None:
                    macs.append((mac_from_bytes(idx), vlan, int(ifindex)))
        if not macs:                                   # switches without per-VLAN contexts
            qfdb = await self._walk(dev, target, FDB["qfdb_port"])
            bridge = await self._walk(dev, target, FDB["bridge_if"])
            for idx, bport in qfdb.items():
                if len(idx) == 7:
                    ifindex = bridge.get((int(bport),))
                    if ifindex is not None:
                        macs.append((mac_from_bytes(idx[1:]), idx[0], int(ifindex)))
        arp = []
        for idx, val in (await self._walk(dev, target, FDB["arp"])).items():
            if len(idx) == 5:
                arp.append((".".join(str(x) for x in idx[1:]), mac_from_bytes(bytes(val))))
        return {"macs": macs, "arp": arp}
