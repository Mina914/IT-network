"""Runtime secrets: SNMPv3 credentials and alert secrets.

Rules this module enforces:
  * Secrets never live in config.yaml, environment variables or the repository.
  * In production they are loaded at start-up from the approved secrets database on
    the internal production server, and kept in memory only.
  * In development only the built-in MOCK credentials are used.
  * Every secret is wrapped in `Secret`, which prints as '***' so it cannot end up in
    logs, tracebacks, API responses or the dashboard by accident.
  * Only SNMPv3 authPriv is accepted (authentication AND encryption).
"""
from __future__ import annotations

import importlib
import ipaddress
import logging
import os
import stat
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("netmon.credentials")


class SecretsError(Exception):
    """Raised when secrets cannot be loaded or break the security policy.
    Messages never contain secret values."""


class Secret:
    """A string that refuses to show itself. Call .reveal() only at the point of use."""
    __slots__ = ("_value",)

    def __init__(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Secret value must be a string")
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __len__(self):
        return len(self._value)

    def __bool__(self):
        return bool(self._value)

    def __repr__(self):
        return "Secret('***')"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("secrets cannot be pickled")


# ---------------------------------------------------------------- SNMPv3 policy
STRONG_AUTH = {"SHA", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"}
STRONG_PRIV = {"AES", "AES128", "AES192", "AES256"}
WEAK_AUTH = {"MD5"}
WEAK_PRIV = {"DES", "3DES"}
MIN_KEY_LEN = 8        # RFC 3414 minimum; Cisco also rejects shorter keys


@dataclass(frozen=True)
class SnmpCredential:
    user: str
    auth_protocol: str
    auth_key: Secret
    priv_protocol: str
    priv_key: Secret


def validate_credential(c: SnmpCredential, where: str, allow_weak_crypto: bool = False) -> SnmpCredential:
    """Enforce SNMPv3 authPriv. `where` names the device; never the key."""
    auth, priv = c.auth_protocol.upper(), c.priv_protocol.upper()
    if not c.user:
        raise SecretsError(f"{where}: SNMPv3 user name is empty")
    if auth in ("", "NONE") or priv in ("", "NONE"):
        raise SecretsError(f"{where}: only SNMPv3 authPriv is allowed (noAuthNoPriv / authNoPriv rejected)")
    allowed_auth = STRONG_AUTH | (WEAK_AUTH if allow_weak_crypto else set())
    allowed_priv = STRONG_PRIV | (WEAK_PRIV if allow_weak_crypto else set())
    if auth not in allowed_auth:
        raise SecretsError(f"{where}: auth protocol {auth} is not allowed (use SHA or SHA-2)")
    if priv not in allowed_priv:
        raise SecretsError(f"{where}: privacy protocol {priv} is not allowed (use AES)")
    if len(c.auth_key) < MIN_KEY_LEN or len(c.priv_key) < MIN_KEY_LEN:
        raise SecretsError(f"{where}: SNMPv3 keys must be at least {MIN_KEY_LEN} characters")
    return SnmpCredential(c.user, auth, c.auth_key, priv, c.priv_key)


# ---------------------------------------------------------------- providers
class SecretsProvider:
    name = "base"

    def snmp_credentials(self) -> dict[str, SnmpCredential]:
        """{device name or '*' for the default: credential}"""
        raise NotImplementedError

    def named_secrets(self) -> dict[str, Secret]:
        """Other secrets, e.g. 'smtp_password', 'teams_webhook'."""
        return {}


class MockProvider(SecretsProvider):
    """Development only. Obviously fake values; matches docs/dev-snmpd.conf."""
    name = "mock"
    USER = "netmon-dev"
    AUTH_KEY = "mock-auth-key-DEV-ONLY"
    PRIV_KEY = "mock-priv-key-DEV-ONLY"

    def snmp_credentials(self):
        return {"*": SnmpCredential(self.USER, "SHA256", Secret(self.AUTH_KEY), "AES", Secret(self.PRIV_KEY))}

    def named_secrets(self):
        return {"smtp_password": Secret("mock-smtp-password-DEV-ONLY"),
                "teams_webhook": Secret("http://127.0.0.1:9/mock-teams-webhook")}


DEFAULT_SNMP_QUERY = (
    "SELECT device_name, snmp_user, auth_protocol, auth_key, priv_protocol, priv_key "
    "FROM netmon_snmp_credentials WHERE enabled = 1"
)
DEFAULT_SECRETS_QUERY = "SELECT name, value FROM netmon_secrets"


def _read_password_file(name_or_path: str) -> Secret:
    """Read the database password from a systemd credential (LoadCredential=) or a
    root-provisioned file that only the netmon user can read."""
    p = Path(name_or_path)
    if not p.is_absolute():
        cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
        if not cred_dir:
            raise SecretsError(
                f"database password credential '{name_or_path}' not found: run under systemd with "
                f"LoadCredential={name_or_path}:<path> (see deploy/netmon.service)")
        p = Path(cred_dir) / name_or_path
    try:
        st = p.stat()
    except OSError:
        raise SecretsError(f"database password file {p} is missing or unreadable") from None
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SecretsError(f"database password file {p} is readable by group/others; chmod 600 it")
    value = p.read_text().strip()
    if not value:
        raise SecretsError(f"database password file {p} is empty")
    return Secret(value)


def _check_internal_host(host: str, allowed: list[str]):
    """The secrets database must be on the internal network."""
    if host in allowed:
        return
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise SecretsError(
            f"secrets database host '{host}' is a name; add it to secrets.allowed_hosts "
            f"after confirming it is the internal production server") from None
    if not (ip.is_private or ip.is_loopback):
        raise SecretsError(f"secrets database host {host} is not an internal address")


class DatabaseProvider(SecretsProvider):
    """Reads secrets from the approved database on the internal production server.

    Works with any Python DB-API 2.0 driver (psycopg, pymysql, pyodbc, oracledb, ...).
    The driver is NOT a NetMon dependency: it is installed on the production server
    after security review. Queries take no parameters, so every driver works.
    """
    name = "database"

    def __init__(self, cfg: dict):
        self.driver = cfg.get("driver", "")
        if not self.driver:
            raise SecretsError("secrets.driver is required (e.g. psycopg, pymysql, pyodbc)")
        self.connect_args = dict(cfg.get("connect") or {})
        for k in self.connect_args:
            if any(w in k.lower() for w in ("password", "passwd", "pwd", "secret", "token")):
                raise SecretsError(f"secrets.connect.{k}: put the database password in the credential file, "
                                   f"not in config.yaml")
        self.password_file = cfg.get("password_file", "netmon-db-password")
        self.password_arg = cfg.get("password_arg", "password")
        self.snmp_query = cfg.get("snmp_query", DEFAULT_SNMP_QUERY)
        self.secrets_query = cfg.get("secrets_query", DEFAULT_SECRETS_QUERY)
        allowed = list(cfg.get("allowed_hosts") or [])
        host = self.connect_args.get("host") or self.connect_args.get("server")
        if host:
            _check_internal_host(str(host), allowed)
        self._rows = None

    def _load(self):
        if self._rows is not None:
            return self._rows
        pw = _read_password_file(self.password_file) if self.password_file else None
        try:
            mod = importlib.import_module(self.driver)
        except ImportError:
            raise SecretsError(f"database driver '{self.driver}' is not installed on this server") from None
        args = dict(self.connect_args)
        if pw is not None:
            args[self.password_arg] = pw.reveal()
        conn = None
        try:
            conn = mod.connect(**args)
            cur = conn.cursor()
            cur.execute(self.snmp_query)
            snmp_rows = cur.fetchall()
            other = []
            if self.secrets_query:
                try:
                    cur.execute(self.secrets_query)
                    other = cur.fetchall()
                except Exception:
                    other = []          # the table for alert secrets is optional
            self._rows = (snmp_rows, other)
            return self._rows
        except SecretsError:
            raise
        except Exception as e:
            msg = str(e)
            if pw is not None and pw.reveal():
                msg = msg.replace(pw.reveal(), "***")
            raise SecretsError(f"could not read secrets database ({type(e).__name__}): {msg[:300]}") from None
        finally:
            args.pop(self.password_arg, None)
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def snmp_credentials(self):
        out = {}
        for row in self._load()[0]:
            device, user, auth_p, auth_k, priv_p, priv_k = (("" if v is None else str(v)) for v in row[:6])
            out[device or "*"] = SnmpCredential(user, auth_p, Secret(auth_k), priv_p, Secret(priv_k))
        return out

    def named_secrets(self):
        return {str(name): Secret(str(value)) for name, value in self._load()[1] if value is not None}


def build_provider(cfg) -> SecretsProvider:
    kind = (cfg.secrets.get("provider") or "").lower()
    if cfg.environment == "production":
        if kind != "database":
            raise SecretsError("production requires secrets.provider: database")
        return DatabaseProvider(cfg.secrets)
    if kind in ("", "mock"):
        return MockProvider()
    if kind == "database":
        return DatabaseProvider(cfg.secrets)
    raise SecretsError(f"unknown secrets provider '{kind}'")


def apply_secrets(cfg, provider: SecretsProvider | None = None):
    """Attach credentials to every device and the alert settings. Fails closed:
    if any device has no valid authPriv credential, NetMon does not start."""
    provider = provider or build_provider(cfg)
    creds = provider.snmp_credentials()
    missing = []
    for d in cfg.devices:
        c = creds.get(d.name) or creds.get("*")
        if c is None:
            missing.append(d.name)
            continue
        d.cred = validate_credential(c, d.name, cfg.allow_weak_crypto)
    if missing:
        raise SecretsError(f"no SNMPv3 credential for: {', '.join(missing)}")

    named = provider.named_secrets()
    if cfg.alerts.email.enabled and cfg.alerts.email.username:
        if "smtp_password" not in named:
            raise SecretsError("email is enabled but secret 'smtp_password' is missing")
        cfg.alerts.email.password = named["smtp_password"]
    if cfg.alerts.teams.enabled:
        if "teams_webhook" not in named:
            raise SecretsError("Teams is enabled but secret 'teams_webhook' is missing")
        cfg.alerts.teams.webhook_url = named["teams_webhook"]
    log.info("loaded SNMPv3 credentials for %d devices from %s provider", len(cfg.devices), provider.name)
