"""Where is this device? MAC and ARP tables from the switches.

* MAC addresses are learned only on edge ports (not switch-to-switch links or trunks),
  so a PC is reported on the port it is plugged into, not on every uplink on the way.
* IP addresses come from the ARP tables (normally on the core).
* After the first full round, a MAC address never seen before raises a "new device"
  event, and a known MAC appearing on another port raises a "device moved" event.
"""
from __future__ import annotations

import re
import time

_HEX = re.compile(r"[^0-9a-f]")


def normalize_mac(s: str) -> str | None:
    h = _HEX.sub("", s.lower())
    if len(h) != 12:
        return None
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def mac_from_bytes(b) -> str:
    return ":".join(f"{x:02x}" for x in bytes(b))


class Inventory:
    def __init__(self, db, monitor, cfg):
        self.db = db
        self.monitor = monitor
        self.cfg = cfg                         # InventoryCfg
        self.arp: dict[str, str] = {}          # mac -> ip
        self._baseline_done: set[str] = set()

    def _edge_port(self, dev, port) -> bool:
        if port is None or port.trunk or port.neighbor:
            return False
        return (dev.cfg.name, port.name) not in self.monitor._link_ports()

    def apply(self, device: str, fdb: list[tuple[str, int | None, int]], arp: list[tuple[str, str]]):
        """fdb: [(mac, vlan, ifindex)], arp: [(ip, mac)]"""
        now = time.time()
        for ip, mac in arp:
            self.arp[mac] = ip
            self.db.execute("UPDATE macs SET ip=? WHERE mac=?", (ip, mac))
        dev = self.monitor.devices.get(device)
        if dev is None:
            return
        known_for_device = bool(self.db.query("SELECT 1 FROM macs WHERE device=? LIMIT 1", (device,)))
        quiet = device not in self._baseline_done and not known_for_device
        self._baseline_done.add(device)
        for mac, vlan, ifindex in fdb:
            port = dev.ports.get(ifindex)
            if not self._edge_port(dev, port):
                continue
            ip = self.arp.get(mac)
            row = self.db.query("SELECT device, port FROM macs WHERE mac=?", (mac,))
            if not row:
                self.db.execute(
                    "INSERT INTO macs(mac, ip, device, port, vlan, first_seen, last_seen, is_new) VALUES (?,?,?,?,?,?,?,?)",
                    (mac, ip, device, port.name, vlan, now, now, 0 if quiet else 1))
                if not quiet and self.cfg.new_device_events:
                    self.monitor._event("warning", device, port.name,
                                        f"New device {mac}{' (' + ip + ')' if ip else ''} on {self.monitor.port_label(dev, port)}"
                                        f"{' VLAN ' + str(vlan) if vlan else ''}")
            else:
                old = row[0]
                if (old["device"], old["port"]) != (device, port.name) and self.cfg.new_device_events:
                    self.monitor._event("info", device, port.name,
                                        f"Device {mac} moved from {old['device']} {old['port']} to {device} {port.name}")
                self.db.execute(
                    "UPDATE macs SET device=?, port=?, vlan=?, last_seen=?, ip=COALESCE(?, ip) WHERE mac=?",
                    (device, port.name, vlan, now, ip, mac))

    def _decorate(self, rows):
        out = []
        for r in rows:
            d = self.monitor.devices.get(r["device"])
            p = d.port_by_name(r["port"]) if d else None
            r["description"] = p.alias if p else ""
            r["port_status"] = (p.oper if p else "unknown")
            r["patch"] = p.patch if p else None
            out.append(r)
        return out

    def search(self, q: str, limit=100) -> list[dict]:
        q = q.strip()
        if not q:
            return []
        mac = normalize_mac(q)
        if mac:
            rows = self.db.query("SELECT * FROM macs WHERE mac=?", (mac,))
        elif re.fullmatch(r"\d{1,3}(\.\d{1,3}){0,3}\.?", q):
            exact = q.count(".") == 3
            rows = self.db.query("SELECT * FROM macs WHERE ip = ? OR (? = 0 AND ip LIKE ?) ORDER BY ip LIMIT ?",
                                 (q, int(exact), q.rstrip(".") + ".%", limit))
        else:
            like = f"%{q.lower()}%"
            hexq = _HEX.sub("", q.lower())
            rows = self.db.query(
                "SELECT * FROM macs WHERE ip LIKE ? OR LOWER(device) LIKE ? OR LOWER(port) = ? "
                "OR (? <> '' AND LENGTH(?) >= 4 AND REPLACE(mac, ':', '') LIKE ?) "
                "ORDER BY last_seen DESC LIMIT ?",
                (like, like, q.lower(), hexq, hexq, f"%{hexq}%", limit))
            # also match on port descriptions (e.g. "Room 305", "PRINTER")
            ql = q.lower()
            hits = {(d.cfg.name, p.name) for d in self.monitor.devices.values() for p in d.ports.values()
                    if ql in (p.alias or "").lower() or (p.patch and ql in (p.patch.get("location") or "").lower())}
            if hits:
                seen = {r["mac"] for r in rows}
                for dn, pn in sorted(hits)[:200]:
                    found = self.db.query("SELECT * FROM macs WHERE device=? AND port=?", (dn, pn))
                    for r in found:
                        if r["mac"] not in seen:
                            rows.append(r)
                            seen.add(r["mac"])
                    if not found:          # the port matches but nothing is plugged in / switched on
                        p = self.monitor.devices[dn].port_by_name(pn)
                        rows.append({"mac": None, "ip": None, "device": dn, "port": pn,
                                     "vlan": p.vlan if p else None, "first_seen": None, "last_seen": None})
        return self._decorate(rows[:limit])

    def recent_new(self, hours=24, limit=200) -> list[dict]:
        rows = self.db.query("SELECT * FROM macs WHERE is_new = 1 AND first_seen >= ? ORDER BY first_seen DESC LIMIT ?",
                             (time.time() - hours * 3600, limit))
        return self._decorate(rows)

    def count(self) -> int:
        return self.db.query("SELECT COUNT(*) AS n FROM macs")[0]["n"]
