"""Availability report: outages, downtime and availability per link and per switch."""
from __future__ import annotations

import time

RANGES = {"day": 86400, "week": 7 * 86400, "month": 30 * 86400}


def merge(intervals):
    """Merge overlapping [start, end] intervals."""
    out = []
    for s, e in sorted(intervals):
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return out


def _clip(alarm, start, end):
    s = max(alarm["raised_ts"], start)
    e = min(alarm["cleared_ts"] or end, end)
    return (s, e) if e > s else None


def build(monitor, history, rng: str = "week", now: float | None = None) -> dict:
    if rng not in RANGES:
        raise ValueError("range must be day, week or month")
    now = now or time.time()
    start, end = now - RANGES[rng], now
    span = end - start
    alarms = monitor.db.alarms_between(start, end)

    by_key: dict[str, list] = {}
    warnings: dict[str, int] = {}
    for a in alarms:
        if a["severity"] == "warning":
            kind = a["key"].split("|")[-1].lstrip("#").split(":")[0]     # cpu, mem, temp, fan, psu, poe, util, err
            warnings[kind] = warnings.get(kind, 0) + 1
            continue
        iv = _clip(a, start, end)
        if iv:
            by_key.setdefault(a["key"], []).append(iv)

    links = []
    for l in monitor.db.links():
        a_key, b_key = f"{l['a_device']}|{l['a_port']}", f"{l['b_device']}|{l['b_port']}"
        ivs = by_key.get(a_key, []) + by_key.get(b_key, []) + \
            by_key.get(f"{l['a_device']}|*", []) + by_key.get(f"{l['b_device']}|*", [])
        m = merge(ivs)
        down = sum(e - s for s, e in m)
        links.append({"link": f"{l['a_device']} {l['a_port']} ⇄ {l['b_device']} {l['b_port']}",
                      "outages": len(m), "downtime_s": round(down),
                      "availability": round(100 * (1 - down / span), 3),
                      "longest_s": round(max((e - s for s, e in m), default=0))})
    links.sort(key=lambda x: (x["availability"], -x["outages"]))

    devices = []
    for name, d in monitor.devices.items():
        m = merge(by_key.get(f"{name}|*", []))
        down = sum(e - s for s, e in m)
        port_alarms = sum(1 for k in by_key if k.startswith(name + "|") and not k.endswith("|*"))
        devices.append({"device": name, "host": d.cfg.host, "floor": d.cfg.floor, "role": d.cfg.role,
                        "outages": len(m), "downtime_s": round(down),
                        "availability": round(100 * (1 - down / span), 3), "port_alarms": port_alarms})
    devices.sort(key=lambda x: (x["availability"], x["device"]))

    errors = []
    for name, d in monitor.devices.items():
        for p in d.ports.values():
            n = p.in_errors + p.out_errors
            if n:
                errors.append({"device": name, "port": p.name, "description": p.alias, "errors": n})
    errors.sort(key=lambda x: -x["errors"])

    speeds = {(n, p.name): p.speed for n, d in monitor.devices.items() for p in d.ports.values() if p.speed}
    util = history.top_utilization(start, speeds) if history else []

    total_down = merge([iv for k, v in by_key.items() for iv in v])
    return {
        "range": rng, "start": start, "end": end, "generated": now,
        "summary": {
            "switches": len(monitor.devices),
            "links": len(links),
            "link_outages": sum(l["outages"] for l in links),
            "switch_outages": sum(d["outages"] for d in devices),
            "worst_availability": round(min([l["availability"] for l in links] + [d["availability"] for d in devices] + [100.0]), 3),
            "time_with_any_problem_s": round(sum(e - s for s, e in total_down)),
            "warnings": warnings,
        },
        "links": links, "devices": devices, "errors": errors[:10], "utilization": util,
    }
