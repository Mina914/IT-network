"""SQLite storage for alarms, the event log and learned topology links."""
from __future__ import annotations

import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    severity TEXT NOT NULL,          -- info | warning | critical | recovery
    device TEXT,
    port TEXT,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS alarms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,               -- device|port  or  device|*
    device TEXT NOT NULL,
    port TEXT,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    raised_ts REAL NOT NULL,
    cleared_ts REAL,
    acked_by TEXT,
    acked_ts REAL,
    notified INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS alarms_active ON alarms(cleared_ts);

CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    a_device TEXT NOT NULL,
    a_port TEXT NOT NULL,
    b_device TEXT NOT NULL,
    b_port TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(a_device, a_port, b_device, b_port)
);

CREATE TABLE IF NOT EXISTS users (
    username   TEXT PRIMARY KEY,
    pw_hash    TEXT NOT NULL,
    role       TEXT NOT NULL,          -- admin | viewer
    created    REAL NOT NULL,
    last_login REAL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,       -- sha256 of the cookie value; the token itself is never stored
    username   TEXT NOT NULL,
    expires    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic (
    device  TEXT NOT NULL,
    port    TEXT NOT NULL,
    res     INTEGER NOT NULL,          -- 300 (5-minute) or 3600 (hourly)
    ts      INTEGER NOT NULL,          -- start of the bucket (unix seconds)
    in_avg  REAL, out_avg REAL, in_max REAL, out_max REAL,
    PRIMARY KEY (device, port, res, ts)
);
CREATE INDEX IF NOT EXISTS traffic_res_ts ON traffic(res, ts);

CREATE TABLE IF NOT EXISTS macs (
    mac        TEXT PRIMARY KEY,       -- aa:bb:cc:dd:ee:ff
    ip         TEXT,
    device     TEXT,
    port       TEXT,
    vlan       INTEGER,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL,
    is_new     INTEGER NOT NULL DEFAULT 0   -- 0 = learned during the first scan (baseline)
);
CREATE INDEX IF NOT EXISTS macs_ip ON macs(ip);
CREATE INDEX IF NOT EXISTS macs_first ON macs(first_seen);
"""


class Database:
    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def _exec(self, sql, args=()):
        with self._lock:
            cur = self._conn.execute(sql, args)
            self._conn.commit()
            return cur

    def _query(self, sql, args=()):
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, args).fetchall()]

    # public helpers for the feature modules (auth, history, inventory, reports)
    def execute(self, sql, args=()):
        return self._exec(sql, args)

    def query(self, sql, args=()):
        return self._query(sql, args)

    def executemany(self, sql, rows):
        with self._lock:
            self._conn.executemany(sql, rows)
            self._conn.commit()

    # ---- events ---------------------------------------------------------
    def add_event(self, severity, device, port, message, ts=None) -> dict:
        ts = ts or time.time()
        cur = self._exec(
            "INSERT INTO events(ts, severity, device, port, message) VALUES (?,?,?,?,?)",
            (ts, severity, device, port, message),
        )
        return {"id": cur.lastrowid, "ts": ts, "severity": severity,
                "device": device, "port": port, "message": message}

    def recent_events(self, limit=200, device=None):
        if device:
            return self._query("SELECT * FROM events WHERE device=? ORDER BY id DESC LIMIT ?", (device, limit))
        return self._query("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))

    def prune_events(self, keep_days=90):
        self._exec("DELETE FROM events WHERE ts < ?", (time.time() - keep_days * 86400,))

    # ---- alarms ---------------------------------------------------------
    def raise_alarm(self, key, device, port, severity, message) -> dict:
        ts = time.time()
        cur = self._exec(
            "INSERT INTO alarms(key, device, port, severity, message, raised_ts) VALUES (?,?,?,?,?,?)",
            (key, device, port, severity, message, ts),
        )
        return self.get_alarm(cur.lastrowid)

    def get_alarm(self, alarm_id):
        rows = self._query("SELECT * FROM alarms WHERE id=?", (alarm_id,))
        return rows[0] if rows else None

    def clear_alarm(self, alarm_id):
        self._exec("UPDATE alarms SET cleared_ts=? WHERE id=? AND cleared_ts IS NULL", (time.time(), alarm_id))
        return self.get_alarm(alarm_id)

    def ack_alarm(self, alarm_id, by):
        self._exec("UPDATE alarms SET acked_by=?, acked_ts=? WHERE id=?", (by, time.time(), alarm_id))
        return self.get_alarm(alarm_id)

    def mark_notified(self, alarm_id):
        self._exec("UPDATE alarms SET notified=1 WHERE id=?", (alarm_id,))

    def active_alarms(self):
        return self._query("SELECT * FROM alarms WHERE cleared_ts IS NULL ORDER BY raised_ts DESC")

    def alarm_history(self, limit=200):
        return self._query("SELECT * FROM alarms ORDER BY id DESC LIMIT ?", (limit,))

    def alarms_between(self, start, end):
        """Alarms that were active at any moment in [start, end]."""
        return self._query(
            "SELECT * FROM alarms WHERE raised_ts <= ? AND (cleared_ts IS NULL OR cleared_ts >= ?) ORDER BY raised_ts",
            (end, start))

    # ---- links ----------------------------------------------------------
    def upsert_link(self, a_dev, a_port, b_dev, b_port):
        (a_dev, a_port), (b_dev, b_port) = sorted([(a_dev, a_port), (b_dev, b_port)])
        ts = time.time()
        cur = self._exec(
            "UPDATE links SET last_seen=? WHERE a_device=? AND a_port=? AND b_device=? AND b_port=?",
            (ts, a_dev, a_port, b_dev, b_port),
        )
        if cur.rowcount == 0:
            self._exec(
                "INSERT INTO links(a_device, a_port, b_device, b_port, first_seen, last_seen) VALUES (?,?,?,?,?,?)",
                (a_dev, a_port, b_dev, b_port, ts, ts),
            )
            return True
        return False

    def links(self):
        return self._query("SELECT * FROM links ORDER BY a_device, a_port")

    def delete_link(self, link_id):
        self._exec("DELETE FROM links WHERE id=?", (link_id,))
