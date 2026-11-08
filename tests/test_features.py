"""Tests for login, traffic history, device finder, patch panels, health/utilisation alarms,
compliance checks, reports and the API's access rules. Local only: no network, mock data."""
import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from netmon import compliance, reports
from netmon.app import create_app
from netmon.auth import Auth, AuthError, hash_password, verify_password
from netmon.config import AlertsCfg, AuthCfg, Config, Device, HistoryCfg, InventoryCfg
from netmon.db import Database
from netmon.history import History
from netmon.inventory import Inventory, normalize_mac
from netmon.monitor import Monitor, Port
from netmon.patchpanels import PatchPanels, parse_csv

PW = "correct-horse-battery"


class NoNotify:
    async def send(self, *a, **k):
        pass


def make_monitor(tmp_path, **kw):
    cfg = Config(db_path=str(tmp_path / "t.db"), alerts=AlertsCfg(notify_delay_seconds=0), **kw)
    m = Monitor(cfg, Database(cfg.db_path), NoNotify())
    m.add_device(Device("CORE", "10.0.0.1", "core", 0))
    m.add_device(Device("F1-SW1", "10.0.1.11", "access", 1))
    return m


def snap(*ports, **extra):
    return {"sysname": "x", "sysdescr": "Cisco IOS (C9300-48P), Version 17.9.4", "uptime": 100, "ports": list(ports), **extra}


def up(name="Te1/1/1", idx=61, **kw):
    d = dict(ifindex=idx, name=name, descr=name, alias="UPLINK to CORE", oper="up", speed=10000, trunk=True,
             neighbor={"device": "CORE.corp.local", "port": "TenGigabitEthernet1/0/1"})
    d.update(kw)
    return Port(**d)


def pc(idx=5, **kw):
    d = dict(ifindex=idx, name=f"Gi1/0/{idx}", descr=f"GigabitEthernet1/0/{idx}", alias=f"Room 10{idx} PC",
             oper="up", speed=1000, vlan=10)
    d.update(kw)
    return Port(**d)


def run(coro):
    return asyncio.run(coro)


# ================================================================ auth
def test_password_hashing():
    h = hash_password(PW)
    assert PW not in h and h.startswith("scrypt$")
    assert verify_password(PW, h) and not verify_password("wrong-password!", h)
    assert hash_password(PW) != h                    # salted


def test_users_sessions_and_lockout(tmp_path):
    a = Auth(Database(str(tmp_path / "a.db")), AuthCfg(max_failures=3, lockout_minutes=10))
    with pytest.raises(AuthError):
        a.add_user("mina", "short", "admin")         # too short
    with pytest.raises(AuthError):
        a.add_user("mina", "mina-password-123", "admin")   # contains username
    with pytest.raises(AuthError):
        a.add_user("bad name!", PW, "admin")
    a.add_user("mina", PW, "admin")
    assert a.has_users()
    tok = a.login("mina", PW, "1.2.3.4")
    assert tok and a.session(tok) == {"username": "mina", "role": "admin"}
    assert a.db.query("SELECT token_hash FROM sessions")[0]["token_hash"] != tok    # only the hash is stored
    a.logout(tok)
    assert a.session(tok) is None
    for _ in range(3):
        assert a.login("mina", "wrong-password!", "5.6.7.8") is None
    with pytest.raises(AuthError):
        a.login("mina", PW, "5.6.7.8")               # locked even with the right password
    assert a.login("ghost", PW, "9.9.9.9") is None   # unknown user: same answer as a wrong password


def test_password_change_logs_out(tmp_path):
    a = Auth(Database(str(tmp_path / "a.db")), AuthCfg())
    a.add_user("ali", PW, "viewer")
    tok = a.login("ali", PW)
    a.set_password("ali", "another-long-pass")
    assert a.session(tok) is None


# ================================================================ API access rules
@pytest.fixture
def client(tmp_path):
    cfg = Config(db_path=str(tmp_path / "api.db"), auth=AuthCfg(enabled=True))
    cfg.devices = [Device("SW1", "127.0.0.1")]
    app = create_app(cfg)                      # no lifespan: nothing is polled
    a = app.state.auth
    a.add_user("admin1", PW, "admin")
    a.add_user("viewer1", PW, "viewer")
    return TestClient(app)


def login(c, user):
    r = c.post("/api/login", json={"username": user, "password": PW}, headers={"X-Requested-With": "netmon"})
    assert r.status_code == 200
    return r


def test_api_requires_login(client):
    assert client.get("/api/state").status_code == 401
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/login").status_code == 200
    assert client.get("/api/auth/status").json() == {"enabled": True, "has_users": True}


def test_login_cookie_and_headers(client):
    r = login(client, "admin1")
    ck = r.headers["set-cookie"].lower()
    assert "httponly" in ck and "samesite=strict" in ck
    r = client.get("/api/me")
    assert r.json()["username"] == "admin1"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


def test_wrong_password(client):
    r = client.post("/api/login", json={"username": "admin1", "password": "nope-nope-nope"},
                    headers={"X-Requested-With": "netmon"})
    assert r.status_code == 401


def test_post_needs_custom_header(client):
    login(client, "admin1")
    assert client.post("/api/devices/SW1/poll").status_code == 403          # no X-Requested-With
    assert client.post("/api/login", json={"username": "a", "password": "b"}).status_code == 403


def test_viewer_cannot_change_things(client):
    login(client, "viewer1")
    h = {"X-Requested-With": "netmon"}
    assert client.get("/api/state").status_code == 200
    assert client.post("/api/alarms/1/ack", headers=h).status_code == 403
    assert client.post("/api/devices/SW1/poll", headers=h).status_code == 403
    assert client.delete("/api/links/1", headers=h).status_code == 403


def test_ack_records_logged_in_user(client):
    login(client, "admin1")
    m = client.app.state.monitor
    a = m.db.raise_alarm("SW1|Gi1/0/1", "SW1", "Gi1/0/1", "critical", "Link down")
    m.active[a["key"]] = a
    r = client.post(f"/api/alarms/{a['id']}/ack", headers={"X-Requested-With": "netmon"})
    assert r.status_code == 200 and r.json()["acked_by"] == "admin1"


# ================================================================ traffic history
def test_history_buckets_and_query(tmp_path):
    db = Database(str(tmp_path / "h.db"))
    h = History(db, HistoryCfg())
    t = 1_700_000_000 // 300 * 300
    for k in range(3):
        h.add("SW", "Te1/1/1", 100e6 * (k + 1), 50e6, t + k * 60)       # same 5-min bucket
    h.add("SW", "Te1/1/1", 10e6, 10e6, t + 300)                           # next bucket -> flush
    rows = db.query("SELECT * FROM traffic")
    assert len(rows) == 1 and rows[0]["in_avg"] == pytest.approx(200e6) and rows[0]["in_max"] == 300e6
    pts = h.query("SW", "Te1/1/1", "day", now=t + 400)["points"]
    assert len(pts) == 2                                                  # stored bucket + open bucket
    h.flush()
    h.rollup(now=t + 3 * 3600)
    assert db.query("SELECT COUNT(*) n FROM traffic WHERE res=3600")[0]["n"] >= 1
    with pytest.raises(ValueError):
        h.query("SW", "Te1/1/1", "year")


# ================================================================ inventory / finder
def test_normalize_mac():
    for s in ("00:1B:44:11:3A:B7", "001b.4411.3ab7", "00-1b-44-11-3a-b7", "001b44113ab7"):
        assert normalize_mac(s) == "00:1b:44:11:3a:b7"
    assert normalize_mac("10.0.0.1") is None


def test_inventory_baseline_new_and_moved(tmp_path):
    m = make_monitor(tmp_path)
    m.apply_snapshot("CORE", snap())
    m.apply_snapshot("F1-SW1", snap(up(), pc(5), pc(6)))
    inv = Inventory(m.db, m, InventoryCfg())
    inv.apply("F1-SW1", [("00:1b:00:00:00:01", 10, 5), ("00:1b:00:00:00:99", 10, 61)], [])   # 2nd is on the uplink
    assert inv.count() == 1                                        # MACs on uplinks are ignored
    assert inv.recent_new() == []                                  # first scan = baseline, no alerts
    inv.apply("F1-SW1", [("00:1b:00:00:00:02", 10, 6)], [("10.1.10.20", "00:1b:00:00:00:02")])
    new = inv.recent_new()
    assert [r["mac"] for r in new] == ["00:1b:00:00:00:02"] and new[0]["ip"] == "10.1.10.20"
    assert any("New device" in e["message"] for e in m.db.recent_events())
    inv.apply("F1-SW1", [("00:1b:00:00:00:01", 10, 6)], [])        # moved from port 5 to port 6
    assert any("moved" in e["message"] for e in m.db.recent_events())
    assert inv.search("001b.0000.0002")[0]["port"] == "Gi1/0/6"
    assert inv.search("10.1.10.20")[0]["mac"] == "00:1b:00:00:00:02"
    assert inv.search("10.1.10")[0]["mac"] == "00:1b:00:00:00:02"  # prefix
    hits = inv.search("Room 105")                                  # description match
    assert hits and hits[0]["device"] == "F1-SW1"


# ================================================================ patch panels
CSV = "panel,panel_port,switch,switch_port,location\nPP-F1-A,1,F1-SW1,GigabitEthernet1/0/5,Room 105\nPP-F1-A,2,,,spare\n"


def test_patch_csv_and_lookup(tmp_path):
    rows = parse_csv(CSV, {"F1-SW1"})
    pp = PatchPanels(rows, {"F1-SW1": 1})
    assert pp.lookup("F1-SW1", "Gi1/0/5") == {"panel": "PP-F1-A", "panel_port": 1, "location": "Room 105"}
    assert pp.to_list()[0]["ports_total"] == 24 and pp.to_list()[0]["floor"] == 1
    with pytest.raises(ValueError):
        parse_csv(CSV, {"OTHER"})                                 # unknown switch
    with pytest.raises(ValueError):
        parse_csv(CSV + "PP-F1-A,1,F1-SW1,Gi1/0/6,x\n", {"F1-SW1"})   # panel port twice
    with pytest.raises(ValueError):
        parse_csv("panel,port\nA,1\n")                             # missing columns
    m = make_monitor(tmp_path)
    m.panels = pp
    m.apply_snapshot("F1-SW1", snap(pc(5)))
    p = m.devices["F1-SW1"].port_by_name("Gi1/0/5")
    assert p.patch["location"] == "Room 105" and "@ PP-F1-A/1 Room 105" in m._port_label(p)


# ================================================================ health, utilisation, errors
def health(cpu=10, temp_state=1, fan_state=1):
    return {"cpu": cpu, "mem_pct": 40, "temps": [{"name": "Inlet", "value": 30, "state": temp_state}],
            "fans": [{"name": "FAN 1", "state": fan_state}], "psus": [{"name": "PS1", "state": 1}]}


def test_health_alarms(tmp_path):
    async def go():
        m = make_monitor(tmp_path)
        m.apply_snapshot("CORE", snap(health=health(cpu=95)))
        assert "CORE|#cpu" not in m.active                        # needs 2 polls in a row
        m.apply_snapshot("CORE", snap(health=health(cpu=96)))
        assert m.active["CORE|#cpu"]["severity"] == "warning"
        m.apply_snapshot("CORE", snap(health=health(cpu=50, fan_state=6)))
        assert "CORE|#cpu" not in m.active
        assert m.active["CORE|#fan:FAN 1"]["severity"] == "critical"
        m.apply_snapshot("CORE", snap(health=health(temp_state=2)))
        assert "CORE|#fan:FAN 1" not in m.active and m.active["CORE|#temp:Inlet"]["severity"] == "warning"
        m.apply_snapshot("F1-SW1", snap(poe={"budget_w": 100, "used_w": 95, "ports": {}}))
        assert "F1-SW1|#poe" in m.active
    run(go())


def test_utilisation_and_error_alarms(tmp_path):
    async def go():
        m = make_monitor(tmp_path)
        m.apply_snapshot("CORE", snap())
        m.apply_snapshot("F1-SW1", snap(up(in_octets=0)))
        dev = m.devices["F1-SW1"]
        for k in (1, 2):                      # ~90% of 10G for two polls
            dev.last_poll = time.time() - 10
            m.apply_snapshot("F1-SW1", snap(up(in_octets=int(k * 10e9 / 8 * 10 * 0.9))))
        assert dev.ports[61].util == pytest.approx(90, abs=2)
        assert "F1-SW1|Te1/1/1|util" in m.active
        dev.last_poll = time.time() - 10
        m.apply_snapshot("F1-SW1", snap(up(in_octets=int(2 * 10e9 / 8 * 10 * 0.9) + 1000, in_errors=500)))
        assert "F1-SW1|Te1/1/1|util" not in m.active
        assert "F1-SW1|Te1/1/1|err" in m.active
    run(go())


def test_vlan_change_event(tmp_path):
    m = make_monitor(tmp_path)
    m.apply_snapshot("F1-SW1", snap(pc(5, vlan=10)))
    m.apply_snapshot("F1-SW1", snap(pc(5, vlan=20)))
    assert any("VLAN changed 10 → 20" in e["message"] for e in m.db.recent_events())


# ================================================================ compliance
def test_compliance_checks(tmp_path):
    m = make_monitor(tmp_path)
    m.apply_snapshot("F1-SW1", snap(pc(5), pc(6, alias="", oper="down"), pc(7, vlan=1),
                                    info={"contact": "", "location": "Floor 1", "ntp": 3}))
    rep = {r["device"]: r for r in compliance.report(m)}
    checks = {c["id"]: c["status"] for c in rep["F1-SW1"]["checks"]}
    assert checks["ntp"] == "fail" and checks["contact"] == "warn" and checks["location"] == "pass"
    assert checks["unused-shutdown"] == "warn" and checks["vlan1"] == "fail"
    assert checks["mgmt-access"] == "unknown"
    assert rep["CORE"]["checks"][0]["status"] == "unknown"           # never polled


# ================================================================ reports
def test_report_merges_both_ends_of_a_link(tmp_path):
    m = make_monitor(tmp_path)
    m.db.upsert_link("CORE", "Te1/0/1", "F1-SW1", "Te1/1/1")
    now = time.time()
    for key, dev, port in (("CORE|Te1/0/1", "CORE", "Te1/0/1"), ("F1-SW1|Te1/1/1", "F1-SW1", "Te1/1/1")):
        a = m.db.raise_alarm(key, dev, port, "critical", "down")
        m.db.execute("UPDATE alarms SET raised_ts=?, cleared_ts=? WHERE id=?", (now - 3600, now - 3000, a["id"]))
    r = reports.build(m, None, "day", now=now)
    link = r["links"][0]
    assert link["outages"] == 1 and link["downtime_s"] == 600            # counted once, not twice
    assert link["availability"] == pytest.approx(100 * (1 - 600 / 86400), abs=0.001)
    assert reports.merge([[0, 5], [3, 8], [10, 12]]) == [[0, 8], [10, 12]]
