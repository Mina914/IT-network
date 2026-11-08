"""Patch panels: which panel port is cabled to which switch port, and where it goes.

Patch panels are passive (no IP, no SNMP), so they are described in a CSV file that
can be kept in Excel ("Save as CSV UTF-8"). Columns:

    panel,panel_port,switch,switch_port,location
    PP-F1-A,1,F1-SW1,Gi1/0/1,Room 101
"""
from __future__ import annotations

import csv
import io
from pathlib import Path

from .monitor import short_ifname

COLUMNS = ("panel", "panel_port", "switch", "switch_port", "location")


def parse_csv(text: str, known_switches: set[str] | None = None) -> list[dict]:
    reader = csv.DictReader(io.StringIO(text.lstrip("﻿")))
    missing = [c for c in COLUMNS[:4] if c not in (reader.fieldnames or [])]
    if missing:
        raise ValueError(f"patch panel CSV is missing column(s): {', '.join(missing)}")
    rows, seen_panel, seen_switch = [], set(), set()
    for i, r in enumerate(reader, start=2):
        panel = (r.get("panel") or "").strip()
        if not panel:
            continue
        try:
            pport = int(str(r.get("panel_port")).strip())
        except ValueError:
            raise ValueError(f"patch panel CSV line {i}: panel_port must be a number") from None
        sw = (r.get("switch") or "").strip()
        sp = short_ifname((r.get("switch_port") or "").strip())
        if known_switches is not None and sw and sw not in known_switches:
            raise ValueError(f"patch panel CSV line {i}: unknown switch '{sw}'")
        if (panel, pport) in seen_panel:
            raise ValueError(f"patch panel CSV line {i}: {panel} port {pport} listed twice")
        if sw and (sw, sp) in seen_switch:
            raise ValueError(f"patch panel CSV line {i}: {sw} {sp} is cabled to two panel ports")
        seen_panel.add((panel, pport))
        if sw:
            seen_switch.add((sw, sp))
        rows.append({"panel": panel, "panel_port": pport, "switch": sw, "switch_port": sp,
                     "location": (r.get("location") or "").strip()})
    return rows


class PatchPanels:
    def __init__(self, rows: list[dict] | None = None, floors: dict[str, int] | None = None):
        self.rows = rows or []
        self.by_switch_port = {(r["switch"], r["switch_port"]): r for r in self.rows if r["switch"]}
        floors = floors or {}
        panels: dict[str, dict] = {}
        for r in self.rows:
            p = panels.setdefault(r["panel"], {"name": r["panel"], "floor": None, "switches": set(), "entries": []})
            p["entries"].append(r)
            if r["switch"]:
                p["switches"].add(r["switch"])
                if p["floor"] is None:
                    p["floor"] = floors.get(r["switch"])
        self.panels = panels

    @classmethod
    def load(cls, path: str, known_switches: set[str], floors: dict[str, int]):
        if not path:
            return cls()
        return cls(parse_csv(Path(path).read_text(encoding="utf-8"), known_switches), floors)

    def lookup(self, switch: str, port: str) -> dict | None:
        r = self.by_switch_port.get((switch, port))
        if not r:
            return None
        return {"panel": r["panel"], "panel_port": r["panel_port"], "location": r["location"]}

    def to_list(self) -> list[dict]:
        out = []
        for p in self.panels.values():
            ports = max((e["panel_port"] for e in p["entries"]), default=0)
            ports = 24 if ports <= 24 else 48 if ports <= 48 else ports
            out.append({"name": p["name"], "floor": p["floor"], "switches": sorted(p["switches"]),
                        "ports_total": ports,
                        "entries": sorted(p["entries"], key=lambda e: e["panel_port"])})
        return sorted(out, key=lambda x: x["name"])
