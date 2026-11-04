"""Load and validate config.yaml.

Any value written as ${NAME} is replaced with the environment variable NAME,
so passwords and keys never have to be stored in the file itself.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand(value):
    if isinstance(value, str):
        def repl(m):
            name = m.group(1)
            if name not in os.environ:
                raise ValueError(f"config uses ${{{name}}} but that environment variable is not set")
            return os.environ[name]
        return _ENV_RE.sub(repl, value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


@dataclass
class SnmpV3:
    user: str = ""
    auth_protocol: str = "SHA"      # MD5, SHA, SHA224, SHA256, SHA384, SHA512
    auth_key: str = ""
    priv_protocol: str = "AES"      # DES, 3DES, AES, AES192, AES256
    priv_key: str = ""
    port: int = 161
    timeout: float = 2.0
    retries: int = 1


@dataclass
class Device:
    name: str
    host: str
    role: str = "access"            # core | distribution | access
    floor: int = 0
    snmp: SnmpV3 = field(default_factory=SnmpV3)


@dataclass
class EmailCfg:
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    starttls: bool = True
    use_ssl: bool = False
    username: str = ""
    password: str = ""
    sender: str = ""
    to: list[str] = field(default_factory=list)


@dataclass
class TeamsCfg:
    enabled: bool = False
    webhook_url: str = ""


@dataclass
class AlertsCfg:
    # "uplinks": alarm only on switch-to-switch links, ports whose description
    #            matches critical_description_regex, and device-down.
    # "all":     alarm on every port that goes down (noisy: PCs turn off!).
    alert_on: str = "uplinks"
    critical_description_regex: str = r"(?i)uplink|trunk|core|server|ap-|wlc|firewall|fw"
    # Wait this long after a link goes down before sending email/Teams.
    # If it comes back within this window nothing is sent (stops flapping spam).
    notify_delay_seconds: int = 15
    send_recovery: bool = True
    email: EmailCfg = field(default_factory=EmailCfg)
    teams: TeamsCfg = field(default_factory=TeamsCfg)


@dataclass
class Config:
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    demo: bool = False
    poll_interval: int = 30
    fail_threshold: int = 3
    syslog_enabled: bool = True
    syslog_port: int = 5514
    db_path: str = "netmon.db"
    alerts: AlertsCfg = field(default_factory=AlertsCfg)
    devices: list[Device] = field(default_factory=list)
    dashboard_url: str = ""


def _snmp_from(d: dict | None, base: SnmpV3 | None = None) -> SnmpV3:
    s = SnmpV3(**vars(base)) if base else SnmpV3()
    for k, v in (d or {}).items():
        if not hasattr(s, k):
            raise ValueError(f"unknown snmp setting: {k}")
        setattr(s, k, v)
    return s


def load_config(path: str | Path) -> Config:
    raw = yaml.safe_load(Path(path).read_text()) or {}
    raw = _expand(raw)

    cfg = Config()
    web = raw.get("web", {})
    cfg.web_host = web.get("host", cfg.web_host)
    cfg.web_port = int(web.get("port", cfg.web_port))
    cfg.dashboard_url = web.get("dashboard_url", "")
    cfg.demo = bool(raw.get("demo", False))
    cfg.db_path = raw.get("db_path", cfg.db_path)

    polling = raw.get("polling", {})
    cfg.poll_interval = int(polling.get("interval_seconds", cfg.poll_interval))
    cfg.fail_threshold = int(polling.get("fail_threshold", cfg.fail_threshold))

    syslog = raw.get("syslog", {})
    cfg.syslog_enabled = bool(syslog.get("enabled", True))
    cfg.syslog_port = int(syslog.get("port", cfg.syslog_port))

    a = raw.get("alerts", {})
    cfg.alerts = AlertsCfg(
        alert_on=a.get("alert_on", "uplinks"),
        critical_description_regex=a.get("critical_description_regex", AlertsCfg.critical_description_regex),
        notify_delay_seconds=int(a.get("notify_delay_seconds", 15)),
        send_recovery=bool(a.get("send_recovery", True)),
        email=EmailCfg(**{("sender" if k == "from" else k): v for k, v in (a.get("email") or {}).items()}),
        teams=TeamsCfg(**(a.get("teams") or {})),
    )
    if cfg.alerts.alert_on not in ("uplinks", "all"):
        raise ValueError("alerts.alert_on must be 'uplinks' or 'all'")

    defaults = _snmp_from(raw.get("snmp_defaults"))
    names = set()
    for d in raw.get("devices", []):
        if d["name"] in names:
            raise ValueError(f"duplicate device name: {d['name']}")
        names.add(d["name"])
        cfg.devices.append(Device(
            name=d["name"],
            host=str(d["host"]),
            role=d.get("role", "access"),
            floor=int(d.get("floor", 0)),
            snmp=_snmp_from(d.get("snmp"), defaults),
        ))
    if not cfg.demo and not cfg.devices:
        raise ValueError("no devices in config (or set demo: true)")
    return cfg
