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

from .config import Device
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

    async def _walk(self, dev, target, oid) -> dict[tuple, object]:
        """Walk one column; returns {index_tuple: value}."""
        base = tuple(int(x) for x in oid.split("."))
        out = {}
        async for err, status, idx, vbs in bulk_walk_cmd(
                self._engine(dev), self._auth(dev), target, ContextData(), 0, 30,
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
        return {
            "sysname": _text(sysname),
            "sysdescr": _text(sysdescr).splitlines()[0][:200],
            "uptime": int(uptime) // 100,
            "ports": ports,
        }
