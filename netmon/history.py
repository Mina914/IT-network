"""Traffic history for the per-port graphs.

Every poll adds a sample per port to an in-memory 5-minute bucket. When the bucket
closes, its average and peak are written to SQLite. Older 5-minute rows are rolled up
into hourly rows, so a week of detail and three months of trend stay small.
"""
from __future__ import annotations

import time

FIVE_MIN, HOUR = 300, 3600
RANGES = {"day": (86400, FIVE_MIN), "week": (7 * 86400, HOUR), "month": (30 * 86400, HOUR)}


class History:
    def __init__(self, db, cfg):
        self.db = db
        self.cfg = cfg                       # HistoryCfg
        self.bucket: int | None = None
        self.acc: dict[tuple[str, str], list[float]] = {}

    def add(self, device: str, port: str, in_bps: float, out_bps: float, ts: float | None = None):
        if not self.cfg.enabled:
            return
        ts = ts or time.time()
        b = int(ts // FIVE_MIN) * FIVE_MIN
        if self.bucket is None:
            self.bucket = b
        elif b != self.bucket:
            self.flush()
            self.bucket = b
        a = self.acc.get((device, port))
        if a is None:
            self.acc[(device, port)] = [in_bps, out_bps, 1, in_bps, out_bps]
        else:
            a[0] += in_bps
            a[1] += out_bps
            a[2] += 1
            a[3] = max(a[3], in_bps)
            a[4] = max(a[4], out_bps)

    def flush(self):
        if not self.acc or self.bucket is None:
            return
        rows = [(d, p, FIVE_MIN, self.bucket, a[0] / a[2], a[1] / a[2], a[3], a[4]) for (d, p), a in self.acc.items()]
        self.db.executemany(
            "INSERT OR REPLACE INTO traffic(device, port, res, ts, in_avg, out_avg, in_max, out_max) "
            "VALUES (?,?,?,?,?,?,?,?)", rows)
        self.acc.clear()

    def rollup(self, now: float | None = None):
        """Build hourly rows for every complete hour not rolled up yet (catches up after
        downtime), then prune old data."""
        now = now or time.time()
        end = int(now // HOUR) * HOUR
        last = self.db.query("SELECT MAX(ts) AS t FROM traffic WHERE res = ?", (HOUR,))[0]["t"]
        oldest = end - self.cfg.keep_5min_days * 86400
        start = max(last + HOUR, oldest) if last is not None else oldest
        self.db.execute(
            "INSERT OR REPLACE INTO traffic(device, port, res, ts, in_avg, out_avg, in_max, out_max) "
            "SELECT device, port, ?, (ts / ?) * ?, AVG(in_avg), AVG(out_avg), MAX(in_max), MAX(out_max) "
            "FROM traffic WHERE res = ? AND ts >= ? AND ts < ? GROUP BY device, port, ts / ?",
            (HOUR, HOUR, HOUR, FIVE_MIN, start, end, HOUR))
        self.db.execute("DELETE FROM traffic WHERE res = ? AND ts < ?", (FIVE_MIN, now - self.cfg.keep_5min_days * 86400))
        self.db.execute("DELETE FROM traffic WHERE res = ? AND ts < ?", (HOUR, now - self.cfg.keep_hourly_days * 86400))

    def query(self, device: str, port: str, rng: str = "day", now: float | None = None) -> dict:
        if rng not in RANGES:
            raise ValueError("range must be day, week or month")
        span, res = RANGES[rng]
        now = now or time.time()
        rows = self.db.query(
            "SELECT ts, in_avg, out_avg, in_max, out_max FROM traffic "
            "WHERE device=? AND port=? AND res=? AND ts >= ? ORDER BY ts",
            (device, port, res, now - span))
        points = [[r["ts"], r["in_avg"], r["out_avg"], r["in_max"], r["out_max"]] for r in rows]
        if res == HOUR:
            # hours not rolled up yet: summarise the recent 5-minute rows
            last = points[-1][0] if points else now - span
            recent = self.db.query(
                "SELECT (ts / ?) * ? AS h, AVG(in_avg) a, AVG(out_avg) b, MAX(in_max) c, MAX(out_max) d FROM traffic "
                "WHERE device=? AND port=? AND res=? AND ts > ? GROUP BY ts / ? ORDER BY h",
                (HOUR, HOUR, device, port, FIVE_MIN, last + HOUR - 1, HOUR))
            points += [[r["h"], r["a"], r["b"], r["c"], r["d"]] for r in recent]
        a = self.acc.get((device, port))
        if a and self.bucket is not None:
            points.append([self.bucket, a[0] / a[2], a[1] / a[2], a[3], a[4]])
        return {"device": device, "port": port, "range": rng, "resolution": res, "points": points}

    def top_utilization(self, start: float, speeds: dict[tuple[str, str], int], limit=10) -> list[dict]:
        rows = self.db.query(
            "SELECT device, port, MAX(MAX(in_max, out_max)) AS peak, AVG(MAX(in_avg, out_avg)) AS avg "
            "FROM traffic WHERE ts >= ? GROUP BY device, port", (start,))
        out = []
        for r in rows:
            sp = speeds.get((r["device"], r["port"]))
            if not sp:
                continue
            out.append({"device": r["device"], "port": r["port"], "speed": sp,
                        "peak_pct": 100 * r["peak"] / (sp * 1e6), "avg_pct": 100 * r["avg"] / (sp * 1e6)})
        out.sort(key=lambda x: -x["peak_pct"])
        return out[:limit]
