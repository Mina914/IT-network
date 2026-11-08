# NetMon — live network monitor for our building

A small, self-hosted monitoring system for Cisco switches:

- **Topology map**: drawn automatically from CDP. Broken links turn **red and blink**.
- **Every switch, every port**: description, up/down, VLAN/trunk, speed, live traffic, errors, CDP neighbour, last change.
- **Front-panel view** of each switch (green = up, red blinking = alarm).
- **Live alarms**: a red banner, a sound, and a counter in the browser tab. Optional **email** and **Teams** messages (off by policy, see section 3).
- **SNMPv3 authPriv, read-only** polling, plus **syslog** for alarms within about a second.
- **No secrets in config files**: SNMPv3 keys are loaded at runtime from your secrets database on the internal production server (see [docs/secrets.md](docs/secrets.md)).
- **No data leaves the server by default**: email and Teams exist but are off unless a security exception is approved.
- Event log, alarm acknowledgement ("acknowledged by Mina"), and alarms saved across restarts.

**Also included:**

| Feature | What it gives you |
|---|---|
| **Login** | Users with `admin` (acknowledge, poll) or `viewer` (read only) roles. scrypt password hashes, lock-out after failed logins, HttpOnly/SameSite cookies, CSP. Manage users with `python -m netmon -c config.yaml user add/list/passwd/role/del`. |
| **Find device** | Type an IP, a MAC in any format, a room, or a description, and get the switch, port, VLAN and patch-panel location. Alerts on **new devices** and **devices that moved**. |
| **Switch health** | CPU, memory, temperature, fans, power supplies and PoE budget, with warnings and alarms. |
| **Utilisation & errors** | A warning when an uplink or server port runs above 80%, or when a port's error counters climb (bad cable or SFP). |
| **Traffic graphs** | Click any port for its day / week / month graph (5-minute averages for 7 days, hourly for 90). |
| **PoE** | Watts per port (⚡ on the front panel) and per switch budget. |
| **Patch panels** | Load a CSV (keep it in Excel). Each port shows `PP-F1-A/12 · Room 112`, panels appear on the map, and alarms tell you the room. |
| **Reports** | `/report`: outages, downtime and availability per uplink and switch, the busiest ports and the error ports, for a day, week or month. Prints or saves as PDF. |
| **Compliance** | Best-practice checks per switch: NTP, location and contact, unused ports shut down, descriptions, VLAN 1, errors, software version, uptime. |
| **Mobile page** | `/m`: alarms and switch status, sized for a phone. |
| **VLAN changes** | An event when an access port's VLAN changes. |

Config backup over SSH is **not included**. It needs write-level access and a new dependency, so it waits for security approval.

![Dashboard](docs/img/dashboard.png)
![Switch port view](docs/img/switch-ports.png)

---

## 1. Try it in demo mode (no switches needed)

```bash
git clone https://github.com/Mina914/IT-network.git netmon && cd netmon
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m netmon --demo
```

Open <http://localhost:8080>. The demo simulates 2 core switches and 5 floors with 2 access
switches each. Click **⚡ Simulate link failure** to see an alarm, and **🔔 Sound** to hear it.

## 2. Development (mock credentials only)

`config.dev.yaml` uses the built-in **mock** SNMPv3 credentials and a local test agent on
`127.0.0.1` ([docs/dev-snmpd.conf](docs/dev-snmpd.conf)). Never use production credentials
or production switches in development.

```bash
.venv/bin/python -m netmon -c config.dev.yaml
```

## 2b. Production

Install it on the internal production server only.

1. **Configure the switches**: follow [docs/cisco-switch-config.md](docs/cisco-switch-config.md)
   (read-only SNMPv3 authPriv user, syslog, CDP, descriptions).
2. **Store the SNMPv3 credentials** in the secrets database, and give NetMon a read-only
   database account: [docs/secrets.md](docs/secrets.md). The DB driver is installed on the
   server after security review.
3. **Write the config** (no secrets in it, and NetMon refuses any):
   ```bash
   cp config.example.yaml /opt/netmon/config.yaml      # IPs, names, floors, secrets DB host
   ```
4. **Start it as a service** (section 5). If any switch lacks a valid authPriv credential,
   NetMon refuses to start and names the switch.
5. In the dashboard, check that every switch is green and the uplinks appear on the map.

## 3. Email and Teams (off by policy)

These send monitoring data off the server, so they're **disabled** and NetMon refuses to
start with them enabled unless `alerts.security_exception` names an approved exception.
With an exception:

- **Email**: prefer an internal SMTP relay. The password is the `smtp_password` row in `netmon_secrets`.
- **Teams**: create a channel Workflow webhook. The URL is the `teams_webhook` row in `netmon_secrets`.

Test with `curl -X POST http://localhost:8080/api/test-notify`.

## 4. When does it alarm?

| Situation | Dashboard | Email / Teams |
|---|---|---|
| Uplink or switch-to-switch link goes down | 🔴 alarm, banner, sound, red link | ✅ after `notify_delay_seconds` (default 15 s) |
| Port with description `UPLINK / SERVER / AP- / FIREWALL…` goes down | 🔴 alarm | ✅ |
| Switch stops answering SNMP (3 polls) | ⛔ alarm, switch red | ✅ |
| User PC port goes down | event log only | ❌ (set `alert_on: all` to change this) |
| Port shut down by an admin | event log only | ❌ |
| Link flaps and recovers within the delay | event log | ❌ (no spam) |
| Alarm clears | alarm removed | ✅ "RECOVERED" with the outage duration |

How the detection works: a switch sends a syslog message the moment a port changes. NetMon
raises the alarm and immediately re-polls that switch over SNMP to confirm. The regular 30 s
SNMP poll catches anything syslog missed.

## 5. Run it as a service (Ubuntu/Debian server or VM)

```bash
sudo useradd -r -s /usr/sbin/nologin netmon
sudo mkdir -p /opt/netmon /etc/netmon && sudo cp -r . /opt/netmon && cd /opt/netmon
sudo python3 -m venv .venv && sudo .venv/bin/pip install -r requirements.txt
# security team: install the reviewed DB driver into .venv and create
# /etc/netmon/credentials/db-password (root, 0600). See docs/secrets.md
sudo chown -R netmon: /opt/netmon
sudo cp deploy/netmon.service /etc/systemd/system/ && sudo systemctl enable --now netmon
journalctl -u netmon -f
```

A small VM (1 vCPU, 1 GB RAM) handles 12 switches easily. The dashboard has **no login yet**,
so only expose port 8080 to the IT/management network.

## 6. Project layout

```
netmon/
  config.py      loads config.yaml (refuses any secret in it)
  credentials.py runtime secrets: authPriv policy, mock (dev) + database (prod) providers
  snmp.py        read-only SNMPv3 authPriv poller: IF-MIB, Cisco VLAN/trunk MIBs, CDP
  syslog.py      parses %LINK-3-UPDOWN / %LINEPROTO-5-UPDOWN for instant alarms
  monitor.py     state, topology learning, alarm rules
  notify.py      email + Teams (Adaptive Card)
  db.py          SQLite: events, alarms, learned links
  simulator.py   demo building
  app.py         web server, REST API, WebSocket live updates
  static/        dashboard (HTML/CSS/JS, vis-network bundled for offline use)
tests/           python -m pytest
docs/            Cisco config guide, screenshots
deploy/          hardened systemd service (database password via LoadCredential)
```

REST API: `GET /api/state`, `GET /api/devices/{name}`, `POST /api/devices/{name}/poll`,
`GET /api/events`, `GET /api/alarms?history=true`, `POST /api/alarms/{id}/ack`,
`DELETE /api/links/{id}` (remove a link from the map after re-cabling), `POST /api/test-notify`.

## 7. Ideas for next versions

- Login (local users or Active Directory/LDAP)
- Traffic graphs per port (history) and high-utilisation / error-rate alarms
- CPU, memory, temperature, PoE and power-supply / fan alarms
- MAC/ARP lookup ("which port is this PC on?")
- Nightly config backups (via SSH)
