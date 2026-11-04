"""Syslog receiver: turns Cisco %LINK / %LINEPROTO messages into instant alarms.

On each switch:
    logging host <monitor-ip> transport udp port 5514
    logging source-interface Vlan<mgmt>
    logging trap notifications
"""
from __future__ import annotations

import asyncio
import logging
import re

log = logging.getLogger("netmon.syslog")

# %LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, changed state to down
# %LINEPROTO-5-UPDOWN: Line protocol on Interface Gi1/0/5, changed state to up
# %LINK-5-CHANGED: Interface GigabitEthernet1/0/5, changed state to administratively down
LINK_RE = re.compile(
    r"%(?P<fac>LINK|LINEPROTO)-\d-(?:UPDOWN|CHANGED):.*?Interface\s+(?P<ifname>[A-Za-z\-]+[0-9/.:]+),"
    r"\s*changed state to\s+(?P<state>administratively down|down|up)",
    re.IGNORECASE,
)


def parse_link_message(text: str):
    m = LINK_RE.search(text)
    if not m:
        return None
    state = m.group("state").lower()
    if state == "administratively down":
        state = "admin_down"
    # LINEPROTO "up" is the true signal a link carries traffic; LINK "up" arrives a bit earlier.
    if state == "up" and m.group("fac").upper() == "LINK":
        return None
    return m.group("ifname"), state


class _Proto(asyncio.DatagramProtocol):
    def __init__(self, monitor):
        self.monitor = monitor

    def datagram_received(self, data, addr):
        text = data.decode("utf-8", "replace")
        parsed = parse_link_message(text)
        if not parsed:
            return
        device = self.monitor.find_device_by_ip(addr[0])
        if not device:
            log.warning("syslog link message from unknown device %s: %s", addr[0], text.strip())
            return
        ifname, state = parsed
        self.monitor.apply_port_status(device, ifname, state, source="syslog")


async def start_syslog(monitor, host: str, port: int):
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(lambda: _Proto(monitor), local_addr=(host, port))
    log.info("syslog listening on udp/%s", port)
    return transport
