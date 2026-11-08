"""Load and validate config.yaml.

config.yaml holds NO secrets. SNMPv3 keys, the SMTP password and the Teams webhook are
loaded at runtime by netmon.credentials from the approved secrets database. Any
secret-looking key in this file makes NetMon refuse to start.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

FORBIDDEN_KEYS = {"auth_key", "priv_key", "authkey", "privkey", "password", "passwd", "community",
                  "webhook_url", "secret", "token", "api_key"}


def _reject_secrets(node, path="config"):
    if isinstance(node, dict):
        for k, v in node.items():
            if str(k).lower() in FORBIDDEN_KEYS:
                raise ValueError(f"{path}.{k}: secrets are not allowed in config.yaml; "
                                 f"store them in the secrets database (see docs/secrets.md)")
            _reject_secrets(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _reject_secrets(v, f"{path}[{i}]")
    elif isinstance(node, str) and "${" in node:
        raise ValueError(f"{path}: ${{ENV}} values are not supported; secrets come from the secrets database")


@dataclass
class SnmpV3:
    """Transport settings only. Credentials live in Device.cred (runtime, in memory)."""
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
    cred: object = field(default=None, repr=False, compare=False)   # credentials.SnmpCredential


@dataclass
class EmailCfg:
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    starttls: bool = True
    use_ssl: bool = False
    username: str = ""
    password: object = field(default="", repr=False)    # credentials.Secret at runtime
    sender: str = ""
    to: list[str] = field(default_factory=list)


@dataclass
class TeamsCfg:
    enabled: bool = False
    webhook_url: object = field(default="", repr=False)  # credentials.Secret at runtime


@dataclass
class AlertsCfg:
    # "uplinks": alarm only on switch-to-switch links, ports whose description
    #            matches critical_description_regex, and device-down.
    # "all":     alarm on every port that goes down (noisy: PCs turn off!).
    alert_on: str = "uplinks"
    critical_description_regex: str = r"(?i)uplink|trunk|core|server|ap-|wlc|firewall|fw"
    # Wait this long after a link goes down before sending email/Teams.
    notify_delay_seconds: int = 15
    send_recovery: bool = True
    notify_warnings: bool = False      # also send email/Teams for warnings (CPU, utilisation, ...)
    # Email and Teams send monitoring data off this server. They stay OFF unless a
    # security exception has been approved; put its reference here.
    security_exception: str = ""
    email: EmailCfg = field(default_factory=EmailCfg)
    teams: TeamsCfg = field(default_factory=TeamsCfg)


@dataclass
class AuthCfg:
    enabled: bool = True
    session_hours: int = 12
    secure_cookies: bool = False      # set true when the dashboard is served over HTTPS
    max_failures: int = 5             # failed logins before a lock-out
    lockout_minutes: int = 10


@dataclass
class Thresholds:
    cpu_percent: float = 90
    memory_percent: float = 90
    utilization_percent: float = 80          # warning when an uplink/server port is busier than this
    utilization_clear_percent: float = 70
    errors_per_poll: int = 50                # new in+out errors between two polls
    poe_budget_percent: float = 90


@dataclass
class InventoryCfg:
    enabled: bool = True                     # MAC / ARP tables for "where is this device?"
    interval_seconds: int = 300
    new_device_events: bool = True


@dataclass
class HistoryCfg:
    enabled: bool = True                     # traffic graphs
    keep_5min_days: int = 7
    keep_hourly_days: int = 90


def _dc(cls, d: dict | None, name: str):
    obj = cls()
    for k, v in (d or {}).items():
        if not hasattr(obj, k):
            raise ValueError(f"unknown setting {name}.{k}")
        setattr(obj, k, v)
    return obj


@dataclass
class Config:
    environment: str = "development"     # development | production
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    demo: bool = False
    poll_interval: int = 30
    fail_threshold: int = 3
    syslog_enabled: bool = True
    syslog_port: int = 5514
    db_path: str = "netmon.db"
    allow_weak_crypto: bool = False      # permit MD5 / DES for very old switches
    secrets: dict = field(default_factory=dict)
    auth: AuthCfg = field(default_factory=AuthCfg)
    thresholds: Thresholds = field(default_factory=Thresholds)
    inventory: InventoryCfg = field(default_factory=InventoryCfg)
    history: HistoryCfg = field(default_factory=HistoryCfg)
    patch_panels_csv: str = ""
    alerts: AlertsCfg = field(default_factory=AlertsCfg)
    devices: list[Device] = field(default_factory=list)
    dashboard_url: str = ""


def _snmp_from(d: dict | None, base: SnmpV3 | None = None) -> SnmpV3:
    s = SnmpV3(**vars(base)) if base else SnmpV3()
    for k, v in (d or {}).items():
        if not hasattr(s, k):
            raise ValueError(f"unknown snmp setting: {k} (credentials belong in the secrets database)")
        setattr(s, k, v)
    return s


def load_config(path: str | Path) -> Config:
    raw = yaml.safe_load(Path(path).read_text()) or {}
    _reject_secrets(raw)

    cfg = Config()
    cfg.environment = raw.get("environment", "development")
    if cfg.environment not in ("development", "production"):
        raise ValueError("environment must be 'development' or 'production'")
    web = raw.get("web", {})
    cfg.web_host = web.get("host", cfg.web_host)
    cfg.web_port = int(web.get("port", cfg.web_port))
    cfg.dashboard_url = web.get("dashboard_url", "")
    cfg.demo = bool(raw.get("demo", False))
    cfg.db_path = raw.get("db_path", cfg.db_path)
    cfg.allow_weak_crypto = bool(raw.get("allow_weak_crypto", False))
    cfg.secrets = dict(raw.get("secrets") or {})
    cfg.auth = _dc(AuthCfg, raw.get("auth"), "auth")
    cfg.thresholds = _dc(Thresholds, raw.get("thresholds"), "thresholds")
    cfg.inventory = _dc(InventoryCfg, raw.get("inventory"), "inventory")
    cfg.history = _dc(HistoryCfg, raw.get("history"), "history")
    cfg.patch_panels_csv = raw.get("patch_panels_csv", "") or ""
    if cfg.environment == "production" and not cfg.auth.enabled:
        raise ValueError("auth.enabled must be true in production")

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
        notify_warnings=bool(a.get("notify_warnings", False)),
        security_exception=str(a.get("security_exception", "") or ""),
        email=EmailCfg(**{("sender" if k == "from" else k): v for k, v in (a.get("email") or {}).items()}),
        teams=TeamsCfg(**(a.get("teams") or {})),
    )
    if cfg.alerts.alert_on not in ("uplinks", "all"):
        raise ValueError("alerts.alert_on must be 'uplinks' or 'all'")
    if (cfg.alerts.email.enabled or cfg.alerts.teams.enabled) and not cfg.alerts.security_exception:
        raise ValueError("email/Teams alerts send monitoring data off this server and are disabled by policy; "
                         "set alerts.security_exception to the approved exception reference to enable them")

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
