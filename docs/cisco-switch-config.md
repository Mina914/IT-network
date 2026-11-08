# Cisco switch configuration for NetMon

Apply this on **every** switch (core and access). Replace:

| Placeholder | Meaning |
|---|---|
| `10.10.0.50` | IP of the NetMon server |
| `Vlan99` | your management SVI (the IP you put in `config.yaml`) |
| `AUTH-KEY` / `PRIV-KEY` | SNMPv3 keys (8+ characters). Production values are kept in the secrets database only (see `secrets.md`). |

> Test on one switch first, then roll out. `snmp-server user` lines are **not shown** in
> `show running-config`; check them with `show snmp user`.

## 1. SNMPv3 (read-only, only from the NetMon server)

```
ip access-list standard NETMON-SNMP
 permit host 10.10.0.50
 deny   any log
!
snmp-server view NETMON-VIEW iso included
snmp-server group NETMON-GRP v3 priv read NETMON-VIEW access NETMON-SNMP
snmp-server user netmon NETMON-GRP v3 auth sha AUTH-KEY priv aes 128 PRIV-KEY access NETMON-SNMP
! MAC address tables per VLAN ("Find device"): Cisco serves them in contexts vlan-10, vlan-20, ...
snmp-server group NETMON-GRP v3 priv context vlan- match prefix read NETMON-VIEW access NETMON-SNMP
!
! keep interface numbering stable across reboots (older IOS; IOS-XE does this by default)
snmp-server ifindex persist
! allow long port descriptions
snmp ifmib ifalias long
```

This is **authPriv** (`v3 priv`): every request is authenticated and encrypted, and the
view is **read-only** (`read` only, no `write` view). NetMon refuses anything weaker.

If your IOS-XE release supports it, use `auth sha-2 256` and `priv aes 256`. Store the
matching `SHA256` / `AES256` in the `auth_protocol` / `priv_protocol` columns of the
secrets database.

The production keys are entered on the switches and in the secrets database by the
people authorised to handle them. Don't paste them into chat, tickets, scripts or this
repository.

What NetMon reads (all read-only): IF-MIB (ports, traffic, errors), CISCO-VLAN-MEMBERSHIP and
VTP (VLANs, trunks), CISCO-CDP (topology), BRIDGE-MIB + ARP (find device), CISCO-PROCESS
(CPU, memory), CISCO-ENVMON (temperature, fans, power), POWER-ETHERNET + CISCO-POWER-ETHERNET-EXT
(PoE), CISCO-NTP and SNMPv2-MIB (compliance).

## 2. Syslog for instant alarms

SNMP polling runs every 30 s. Syslog messages make link-down alarms appear in about a second.

```
service timestamps log datetime msec localtime show-timezone
logging source-interface Vlan99
logging host 10.10.0.50 transport udp port 5514
logging trap notifications
```

`logging source-interface` matters: NetMon identifies the switch by the source IP of the
message, so it must match the `host:` in `config.yaml`.

Make sure link messages are not turned off on uplinks:

```
interface TenGigabitEthernet1/1/1
 logging event link-status
```

## 3. CDP (draws the topology automatically)

CDP is on by default on Cisco. Check it with `show cdp neighbors`. If it's off:

```
cdp run
interface range TenGigabitEthernet1/1/1 - 2
 cdp enable
```

The topology map is drawn from CDP. Once NetMon has seen a link, it remembers it, so a
broken link stays on the map in **red** even after CDP forgets the neighbour.

## 4. Good port descriptions = good alarms

NetMon shows the description of every port, and uses it to decide what's important.
Ports whose description contains `UPLINK`, `TRUNK`, `CORE`, `SERVER`, `AP-`, `WLC` or
`FIREWALL` raise an alarm when they go down (this list is set by `critical_description_regex`).

```
interface TenGigabitEthernet1/1/1
 description UPLINK to CORE-SW1 Te1/0/1
interface GigabitEthernet1/0/47
 description AP-F1-01
interface GigabitEthernet1/0/5
 description F1 Room 101 PC
```

## 5. Firewall rules on the NetMon server

| Direction | Protocol/port | Purpose |
|---|---|---|
| server → switches | UDP 161 | SNMP polling |
| switches → server | UDP 5514 | syslog |
| users → server | TCP 8080 | dashboard |
| server → mail / Internet | TCP 587, TCP 443 | email, Teams |
