import asyncio

import pytest

from netmon.config import AlertsCfg, Config, Device
from netmon.db import Database
from netmon.monitor import Monitor, Port, short_hostname, short_ifname
from netmon.syslog import parse_link_message


class FakeNotifier:
    def __init__(self):
        self.sent = []

    async def send(self, alarm, ctx, recovered):
        self.sent.append(("recovered" if recovered else "alarm", alarm["message"]))


def make(tmp_path, delay=0, alert_on="uplinks"):
    cfg = Config(db_path=str(tmp_path / "t.db"), alerts=AlertsCfg(notify_delay_seconds=delay, alert_on=alert_on))
    n = FakeNotifier()
    m = Monitor(cfg, Database(cfg.db_path), n)
    m.add_device(Device("CORE", "10.0.0.1", "core", 0))
    m.add_device(Device("F1-SW1", "10.0.1.11", "access", 1))
    return m, n


def snap(*ports):
    return {"sysname": "x", "sysdescr": "Cisco", "uptime": 100, "ports": list(ports)}


def uplink(oper="up", nb=True):
    return Port(ifindex=61, name="Te1/1/1", descr="TenGigabitEthernet1/1/1", alias="UPLINK to CORE",
                oper=oper, speed=10000, trunk=True,
                neighbor={"device": "CORE.corp.local", "port": "TenGigabitEthernet1/0/1"} if nb else None)


def pc(oper="up"):
    return Port(ifindex=5, name="Gi1/0/5", descr="GigabitEthernet1/0/5", alias="Room 101 PC", oper=oper, vlan=10)


async def settle():
    await asyncio.sleep(0.05)


def test_names():
    assert short_ifname("GigabitEthernet1/0/5") == "Gi1/0/5"
    assert short_ifname("TenGigabitEthernet1/1/1") == "Te1/1/1"
    assert short_ifname("Port-channel1") == "Po1"
    assert short_hostname("F1-SW1.corp.local") == "f1-sw1"
    assert short_hostname("N9K(FDO1234)") == "n9k"


@pytest.mark.parametrize("msg,expected", [
    ("%LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, changed state to down", ("GigabitEthernet1/0/5", "down")),
    ("<187>12: *Nov 4: %LINEPROTO-5-UPDOWN: Line protocol on Interface Te1/1/1, changed state to up", ("Te1/1/1", "up")),
    ("%LINK-5-CHANGED: Interface Gi1/0/2, changed state to administratively down", ("Gi1/0/2", "admin_down")),
    ("%LINK-3-UPDOWN: Interface Gi1/0/5, changed state to up", None),     # wait for LINEPROTO up
    ("%SYS-5-CONFIG_I: Configured from console", None),
])
def test_syslog_parse(msg, expected):
    assert parse_link_message(msg) == expected


def test_uplink_down_raises_alarm_and_notifies(tmp_path):
    async def run():
        m, n = make(tmp_path)
        m.apply_snapshot("CORE", snap())
        m.apply_snapshot("F1-SW1", snap(uplink(), pc()))
        assert len(m.db.links()) == 1                      # learned from CDP
        m.apply_port_status("F1-SW1", "TenGigabitEthernet1/1/1", "down")
        assert list(m.active) == ["F1-SW1|Te1/1/1"]
        await settle()
        assert n.sent == [("alarm", "Link down: F1-SW1 Te1/1/1 (UPLINK to CORE)")]
        # link comes back (CDP neighbour returns)
        m.apply_snapshot("F1-SW1", snap(uplink("up"), pc()))
        assert not m.active
        await settle()
        assert n.sent[-1][0] == "recovered"
    asyncio.run(run())


def test_pc_port_down_is_only_an_event(tmp_path):
    async def run():
        m, n = make(tmp_path)
        m.apply_snapshot("F1-SW1", snap(uplink(), pc()))
        m.apply_snapshot("F1-SW1", snap(uplink(), pc("down")))
        await settle()
        assert not m.active and not n.sent
        assert any("Gi1/0/5" in (e["port"] or "") for e in m.db.recent_events())
    asyncio.run(run())


def test_alert_on_all(tmp_path):
    async def run():
        m, _ = make(tmp_path, alert_on="all")
        m.apply_snapshot("F1-SW1", snap(pc()))
        m.apply_snapshot("F1-SW1", snap(pc("down")))
        assert "F1-SW1|Gi1/0/5" in m.active
    asyncio.run(run())


def test_flap_within_delay_sends_nothing(tmp_path):
    async def run():
        m, n = make(tmp_path, delay=0.2)
        m.apply_snapshot("CORE", snap())
        m.apply_snapshot("F1-SW1", snap(uplink(), pc()))
        m.apply_port_status("F1-SW1", "Te1/1/1", "down")
        m.apply_port_status("F1-SW1", "Te1/1/1", "up")
        await asyncio.sleep(0.3)
        assert not m.active and not n.sent
    asyncio.run(run())


def test_known_link_stays_critical_after_cdp_ages_out(tmp_path):
    async def run():
        m, _ = make(tmp_path)
        m.apply_snapshot("CORE", snap())
        m.apply_snapshot("F1-SW1", snap(uplink(), pc()))
        # next poll: link is down and CDP neighbour has disappeared
        m.apply_snapshot("F1-SW1", snap(uplink("down", nb=False), pc()))
        assert "F1-SW1|Te1/1/1" in m.active
        assert m.links()[0]["status"] == "down"
    asyncio.run(run())


def test_admin_shutdown_clears_alarm(tmp_path):
    async def run():
        m, _ = make(tmp_path)
        m.apply_snapshot("CORE", snap())
        m.apply_snapshot("F1-SW1", snap(uplink(), pc()))
        m.apply_port_status("F1-SW1", "Te1/1/1", "down")
        assert m.active
        m.apply_port_status("F1-SW1", "Te1/1/1", "admin_down")
        assert not m.active
    asyncio.run(run())


def test_device_unreachable_after_threshold(tmp_path):
    async def run():
        m, n = make(tmp_path)
        m.apply_snapshot("F1-SW1", snap(uplink(), pc()))
        for _ in range(m.cfg.fail_threshold - 1):
            m.apply_poll_failure("F1-SW1", "timeout")
        assert not m.active
        m.apply_poll_failure("F1-SW1", "timeout")
        assert "F1-SW1|*" in m.active
        assert m.device_dict(m.devices["F1-SW1"])["status"] == "down"
        await settle()
        m.apply_snapshot("F1-SW1", snap(uplink(), pc()))
        assert not m.active
        await settle()
        assert [k for k, _ in n.sent] == ["alarm", "recovered"]
    asyncio.run(run())


def test_alarm_survives_restart_without_duplicate(tmp_path):
    async def run():
        m, _ = make(tmp_path)
        m.apply_snapshot("CORE", snap())
        m.apply_snapshot("F1-SW1", snap(uplink(), pc()))
        m.apply_port_status("F1-SW1", "Te1/1/1", "down")
        # restart: new monitor on the same database, link still down
        m2, _ = make(tmp_path)
        assert "F1-SW1|Te1/1/1" in m2.active
        m2.apply_snapshot("CORE", snap())
        m2.apply_snapshot("F1-SW1", snap(uplink("down", nb=False), pc()))
        assert len(m2.db.active_alarms()) == 1
    asyncio.run(run())
