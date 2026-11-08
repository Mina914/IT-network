"""Best-practice checks per switch, using only what read-only SNMP can see.

Checks that need the running-config (Telnet off, SSH v2, password encryption, ...)
are reported as "not checked": they need config access (the postponed config-backup feature).
"""
from __future__ import annotations

import re
from collections import Counter

PASS, WARN, FAIL, UNKNOWN = "pass", "warn", "fail", "unknown"
NTP_OK = {5: "synchronised to reference clock", 6: "synchronised to NTP server"}
NTP_TEXT = {1: "unknown", 2: "NTP not running", 3: "not synchronised", 4: "synchronised to local clock only"}
_VERSION = re.compile(r"Version\s+([\w.()]+)")
_MODEL = re.compile(r"\(([^)]+)\)")


def _names(ports, n=6):
    names = [p.name for p in ports]
    return ", ".join(names[:n]) + (f" +{len(names) - n} more" if len(names) > n else "")


def check_device(dev, link_ports: set, fleet_versions: dict) -> list[dict]:
    res = []

    def add(cid, title, status, detail=""):
        res.append({"id": cid, "title": title, "status": status, "detail": detail})

    if dev.reachable is not True:
        add("reachable", "Switch answers SNMPv3", FAIL if dev.reachable is False else UNKNOWN,
            dev.last_error or "not polled yet")
        return res
    add("snmpv3", "SNMPv3 authPriv, read-only", PASS, "polled successfully with authentication + encryption")

    info = dev.info or {}
    ntp = info.get("ntp")
    if ntp in NTP_OK:
        add("ntp", "Clock synchronised with NTP", PASS, NTP_OK[ntp])
    elif ntp is None:
        add("ntp", "Clock synchronised with NTP", UNKNOWN, "CISCO-NTP-MIB not available")
    else:
        add("ntp", "Clock synchronised with NTP", FAIL, NTP_TEXT.get(ntp, str(ntp)) + " (logs and alarms get wrong times)")

    add("location", "snmp-server location set", PASS if info.get("location") else WARN,
        info.get("location") or "add: snmp-server location <building/floor/rack>")
    add("contact", "snmp-server contact set", PASS if info.get("contact") else WARN,
        info.get("contact") or "add: snmp-server contact <team email/phone>")

    ports = [p for p in dev.ports.values() if not p.name.startswith(("Po", "Vl"))]
    unused = [p for p in ports if p.admin == "up" and p.oper != "up" and not p.alias]
    add("unused-shutdown", "Unused ports are shut down", PASS if not unused else WARN,
        "all unused ports are shut down" if not unused else
        f"{len(unused)} enabled port(s) with no description and no link: {_names(unused)}")

    nodesc = [p for p in ports if p.oper == "up" and not p.alias]
    add("descriptions", "Active ports have a description", PASS if not nodesc else WARN,
        "all active ports are described" if not nodesc else f"{len(nodesc)} port(s): {_names(nodesc)}")

    uplinks_nodesc = [p for p in ports if ((dev.cfg.name, p.name) in link_ports or p.neighbor) and not p.alias]
    add("uplink-descriptions", "Uplinks have a description", PASS if not uplinks_nodesc else FAIL,
        "all uplinks are described" if not uplinks_nodesc else _names(uplinks_nodesc))

    vlan1 = [p for p in ports if not p.trunk and p.vlan == 1 and p.oper == "up"]
    add("vlan1", "No user ports in VLAN 1", PASS if not vlan1 else FAIL,
        "no active access ports in VLAN 1" if not vlan1 else f"{len(vlan1)} port(s): {_names(vlan1)}")

    errs = [p for p in ports if p.in_errors + p.out_errors > 1000]
    add("errors", "No ports with many errors", PASS if not errs else WARN,
        "no port above 1000 errors since the switch booted" if not errs else
        f"{len(errs)} port(s) (cabling/SFP?): {_names(sorted(errs, key=lambda p: -(p.in_errors + p.out_errors)))}")

    m_ver = _VERSION.search(dev.sysdescr or "")
    m_mod = _MODEL.search(dev.sysdescr or "")
    if m_ver:
        model = m_mod.group(1) if m_mod else "?"
        common = fleet_versions.get(model)
        add("version", "Same software version as similar switches",
            PASS if not common or common == m_ver.group(1) else WARN,
            f"{m_ver.group(1)}" + ("" if not common or common == m_ver.group(1) else f" (most {model} run {common})"))
    else:
        add("version", "Same software version as similar switches", UNKNOWN, "version not found in sysDescr")

    days = (dev.uptime or 0) / 86400
    add("uptime", "Rebooted (patched) in the last year", PASS if days < 365 else WARN,
        f"up {int(days)} days" + ("" if days < 365 else ": probably missing security updates"))

    add("mgmt-access", "Telnet off / SSH v2 only / password encryption", UNKNOWN,
        "needs config access (config backup feature, pending security approval)")
    return res


def fleet_versions(devices) -> dict:
    by_model: dict[str, Counter] = {}
    for d in devices:
        mv, mm = _VERSION.search(d.sysdescr or ""), _MODEL.search(d.sysdescr or "")
        if mv:
            by_model.setdefault(mm.group(1) if mm else "?", Counter())[mv.group(1)] += 1
    return {m: c.most_common(1)[0][0] for m, c in by_model.items()}


def report(monitor) -> list[dict]:
    devs = list(monitor.devices.values())
    lp = monitor._link_ports()
    fv = fleet_versions(devs)
    out = []
    for d in devs:
        checks = check_device(d, lp, fv)
        scored = [c for c in checks if c["status"] != UNKNOWN]
        score = round(100 * sum(c["status"] == PASS for c in scored) / len(scored)) if scored else None
        out.append({"device": d.cfg.name, "host": d.cfg.host, "role": d.cfg.role, "floor": d.cfg.floor,
                    "score": score,
                    "fails": sum(c["status"] == FAIL for c in checks),
                    "warns": sum(c["status"] == WARN for c in checks),
                    "checks": checks})
    return out
