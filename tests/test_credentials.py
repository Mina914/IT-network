"""Security tests: authPriv only, read-only SNMP, secrets never in config or logs.
All credentials here are mock values."""
import ast
import logging
import os
import sqlite3
from pathlib import Path

import pytest

from netmon import credentials as C
from netmon.config import Config, Device, load_config
from netmon.credentials import (
    DatabaseProvider, MockProvider, Secret, SecretsError, SnmpCredential,
    apply_secrets, build_provider, validate_credential,
)

MOCK_AUTH, MOCK_PRIV = "mock-auth-key-TEST", "mock-priv-key-TEST"


def cred(auth="SHA256", priv="AES", ak=MOCK_AUTH, pk=MOCK_PRIV, user="netmon-test"):
    return SnmpCredential(user, auth, Secret(ak), priv, Secret(pk))


# ---------------------------------------------------------------- Secret masking
def test_secret_never_prints(caplog):
    s = Secret(MOCK_AUTH)
    assert MOCK_AUTH not in repr(s) and MOCK_AUTH not in str(s) and MOCK_AUTH not in f"{s}"
    c = cred()
    d = Device("SW", "10.0.0.1", cred=c)
    assert MOCK_AUTH not in repr(c) and MOCK_PRIV not in repr(c)
    assert MOCK_AUTH not in repr(d)
    with caplog.at_level(logging.DEBUG):
        logging.getLogger("t").info("cred=%s device=%r", c, d)
    assert MOCK_AUTH not in caplog.text and MOCK_PRIV not in caplog.text
    with pytest.raises(TypeError):
        import pickle
        pickle.dumps(s)
    assert s.reveal() == MOCK_AUTH


# ---------------------------------------------------------------- authPriv policy
@pytest.mark.parametrize("auth,priv", [("NONE", "NONE"), ("SHA", "NONE"), ("", "AES"), ("MD5", "AES"),
                                       ("SHA", "DES"), ("SHA", "3DES"), ("FOO", "AES")])
def test_policy_rejects_non_authpriv_and_weak(auth, priv):
    with pytest.raises(SecretsError):
        validate_credential(cred(auth, priv), "SW")


def test_policy_accepts_strong_and_weak_only_when_allowed():
    assert validate_credential(cred("sha256", "aes256"), "SW").auth_protocol == "SHA256"
    validate_credential(cred("MD5", "DES"), "SW", allow_weak_crypto=True)


def test_policy_rejects_short_keys_without_showing_them():
    with pytest.raises(SecretsError) as e:
        validate_credential(cred(ak="short"), "SW")
    assert "short" not in str(e.value)


# ---------------------------------------------------------------- read-only SNMP
def test_snmp_module_is_read_only():
    src = (Path(__file__).parent.parent / "netmon" / "snmp.py").read_text()
    names = {n.id for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Name)}
    names |= {a.name for n in ast.walk(ast.parse(src)) if isinstance(n, ast.ImportFrom) for a in n.names}
    assert not {"set_cmd", "setCmd", "usmNoAuthProtocol", "usmNoPrivProtocol", "CommunityData"} & names


def test_snmp_auth_uses_runtime_credential():
    from netmon.snmp import SnmpBackend, SnmpError
    b = SnmpBackend()
    with pytest.raises(SnmpError):
        b._auth(Device("SW", "10.0.0.1"))                  # no credential loaded
    u = b._auth(Device("SW", "10.0.0.1", cred=validate_credential(cred(), "SW")))
    assert u.userName == "netmon-test"
    assert str(u.security_level) == "authPriv"
    assert MOCK_AUTH not in repr(u) and MOCK_PRIV not in repr(u)


# ---------------------------------------------------------------- config hygiene
def write(tmp_path, text):
    p = tmp_path / "c.yaml"
    p.write_text(text)
    return p


DEVICES = "devices:\n  - {name: SW1, host: 10.0.0.1}\n"


@pytest.mark.parametrize("bad", [
    "snmp_defaults: {auth_key: x}\n", "snmp_defaults: {priv_key: x}\n",
    "alerts: {email: {password: x}}\n", "alerts: {teams: {webhook_url: x}}\n",
    "secrets: {connect: {host: 10.0.0.9, password: x}}\n", "web: {dashboard_url: '${HOME}'}\n",
])
def test_config_refuses_secrets(tmp_path, bad):
    with pytest.raises(ValueError):
        load_config(write(tmp_path, bad + DEVICES))


def test_alerts_need_security_exception(tmp_path):
    with pytest.raises(ValueError):
        load_config(write(tmp_path, "alerts: {teams: {enabled: true}}\n" + DEVICES))
    cfg = load_config(write(tmp_path, "alerts: {security_exception: SEC-123, teams: {enabled: true}}\n" + DEVICES))
    assert cfg.alerts.teams.enabled


def test_example_configs_load():
    root = Path(__file__).parent.parent
    assert load_config(root / "config.example.yaml").environment == "production"
    assert load_config(root / "config.dev.yaml").environment == "development"


# ---------------------------------------------------------------- providers
def test_production_refuses_mock():
    with pytest.raises(SecretsError):
        build_provider(Config(environment="production", secrets={"provider": "mock"}))
    assert isinstance(build_provider(Config(environment="development")), MockProvider)


def test_database_host_must_be_internal():
    with pytest.raises(SecretsError):
        DatabaseProvider({"driver": "x", "connect": {"host": "8.8.8.8"}})
    with pytest.raises(SecretsError):
        DatabaseProvider({"driver": "x", "connect": {"host": "secrets.example.com"}})
    DatabaseProvider({"driver": "x", "connect": {"host": "10.20.0.5"}})
    DatabaseProvider({"driver": "x", "connect": {"host": "vault-db.corp.local"}, "allowed_hosts": ["vault-db.corp.local"]})


def make_db(path):
    con = sqlite3.connect(path)
    con.executescript(f"""
        CREATE TABLE netmon_snmp_credentials (device_name TEXT, snmp_user TEXT, auth_protocol TEXT,
            auth_key TEXT, priv_protocol TEXT, priv_key TEXT, enabled INTEGER);
        INSERT INTO netmon_snmp_credentials VALUES ('*', 'netmon-test', 'SHA256', '{MOCK_AUTH}', 'AES', '{MOCK_PRIV}', 1);
        INSERT INTO netmon_snmp_credentials VALUES ('OLD', 'old', 'SHA', '{MOCK_AUTH}', 'NONE', '', 1);
        CREATE TABLE netmon_secrets (name TEXT, value TEXT);
        INSERT INTO netmon_secrets VALUES ('teams_webhook', 'http://127.0.0.1:9/mock');
    """)
    con.commit()
    con.close()


def db_cfg(tmp_path, devices):
    make_db(tmp_path / "s.db")
    cfg = Config(environment="development",
                 secrets={"provider": "database", "driver": "sqlite3", "password_file": None,
                          "connect": {"database": str(tmp_path / "s.db")}})
    cfg.devices = [Device(n, "10.0.0.1") for n in devices]
    return cfg


def test_database_provider_loads_default_credential(tmp_path):
    cfg = db_cfg(tmp_path, ["SW1", "SW2"])
    apply_secrets(cfg)
    assert all(d.cred.user == "netmon-test" and d.cred.auth_key.reveal() == MOCK_AUTH for d in cfg.devices)


def test_apply_secrets_fails_closed_on_authnopriv_row(tmp_path):
    cfg = db_cfg(tmp_path, ["SW1", "OLD"])
    with pytest.raises(SecretsError) as e:
        apply_secrets(cfg)
    assert "OLD" in str(e.value) and MOCK_AUTH not in str(e.value)


def test_apply_secrets_requires_every_device(tmp_path):
    cfg = Config()
    cfg.devices = [Device("SW1", "10.0.0.1")]

    class Empty(C.SecretsProvider):
        def snmp_credentials(self):
            return {}
    with pytest.raises(SecretsError):
        apply_secrets(cfg, Empty())


def test_password_file_permissions(tmp_path, monkeypatch):
    f = tmp_path / "netmon-db-password"
    f.write_text("mock-db-password\n")
    os.chmod(f, 0o644)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    with pytest.raises(SecretsError):
        C._read_password_file("netmon-db-password")
    os.chmod(f, 0o600)
    assert C._read_password_file("netmon-db-password").reveal() == "mock-db-password"


def test_db_errors_do_not_leak_password(tmp_path, monkeypatch):
    f = tmp_path / "pw"
    f.write_text("mock-db-password")
    os.chmod(f, 0o600)

    class FakeDriver:
        @staticmethod
        def connect(**kw):
            raise RuntimeError(f"login failed for password={kw['password']}")
    monkeypatch.setitem(__import__("sys").modules, "fake_driver_mod", FakeDriver)
    p = DatabaseProvider({"driver": "fake_driver_mod", "password_file": str(f), "connect": {"host": "10.0.0.9"}})
    with pytest.raises(SecretsError) as e:
        p.snmp_credentials()
    assert "mock-db-password" not in str(e.value) and "***" in str(e.value)
