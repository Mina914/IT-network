# Credentials and secrets

NetMon follows these rules:

| Rule | How it's enforced |
|---|---|
| SNMPv3 **authPriv only** | `credentials.validate_credential` rejects noAuthNoPriv, authNoPriv, empty or short keys. `snmp.py` has no code path for anything else. |
| Strong crypto | Auth SHA or SHA-2, privacy AES. MD5 and DES are refused unless `allow_weak_crypto: true`. |
| **Read-only** SNMP | Only GET and GETBULK are used. `set_cmd` is never imported (a test checks this). On the switches the SNMP view is read-only (see `cisco-switch-config.md`). |
| No secrets in config or repository | `config.py` refuses `auth_key`, `priv_key`, `password`, `webhook_url`, `token`, `${ENV}` and similar. |
| Secrets loaded **only at runtime** from the approved store | `DatabaseProvider` reads them at start-up from the secrets database on the internal production server and keeps them **in memory only** (nothing is written to disk). |
| Production never uses mock values | With `environment: production`, only `provider: database` is accepted. |
| Secrets never logged or shown | Values are wrapped in `Secret`, which prints as `***`. Database errors are scrubbed. `httpx` URL logging is turned off. Core dumps are disabled in the service. |
| Fail closed | If any switch has no valid authPriv credential, NetMon does not start. The error names the switch, never the key. |
| No monitoring data to external services | Email and Teams are off. Enabling them requires `alerts.security_exception`. The dashboard loads no external scripts or fonts (vis-network is bundled). |

## Development

Development uses only the built-in **mock** credentials (`MockProvider`):

| | Value |
|---|---|
| user | `netmon-dev` |
| auth | SHA-256 / `mock-auth-key-DEV-ONLY` |
| priv | AES-128 / `mock-priv-key-DEV-ONLY` |

`config.dev.yaml` points at a local test agent on `127.0.0.1` (`docs/dev-snmpd.conf`).
Don't put production credentials in the development environment, and don't point it at
production switches.

## Production: the secrets database

NetMon connects with any Python DB-API driver. **The driver is not part of
`requirements.txt`.** Your security team reviews it and installs it on the production
server only, for example `pip install psycopg[binary]` for PostgreSQL, `pymysql` for
MySQL/MariaDB, or `pyodbc` for SQL Server.

Use a **dedicated read-only account** that can only `SELECT` these two tables (or views).
The default queries take no parameters:

```sql
-- SNMPv3 credentials. device_name '*' is the default for every switch;
-- a row with a switch's name (as in config.yaml) overrides it.
CREATE TABLE netmon_snmp_credentials (
    device_name   VARCHAR(64)  NOT NULL,
    snmp_user     VARCHAR(64)  NOT NULL,
    auth_protocol VARCHAR(10)  NOT NULL,   -- SHA | SHA256 | SHA384 | SHA512
    auth_key      VARCHAR(128) NOT NULL,
    priv_protocol VARCHAR(10)  NOT NULL,   -- AES | AES192 | AES256
    priv_key      VARCHAR(128) NOT NULL,
    enabled       SMALLINT     NOT NULL DEFAULT 1,
    PRIMARY KEY (device_name)
);

-- Optional, only needed if email/Teams are enabled under a security exception.
-- Names used: smtp_password, teams_webhook
CREATE TABLE netmon_secrets (
    name  VARCHAR(64)  PRIMARY KEY,
    value VARCHAR(2048) NOT NULL
);

GRANT SELECT ON netmon_snmp_credentials, netmon_secrets TO netmon_ro;
```

If your database encrypts these columns (column encryption, a view that decrypts with a
database key, and so on), point `secrets.snmp_query` at a view that returns the same six
columns in this order: `device_name, snmp_user, auth_protocol, auth_key, priv_protocol, priv_key`.

### The database password

The password of the `netmon_ro` account is the one bootstrap secret. It's delivered by
**systemd credentials**, never an environment variable or `config.yaml`:

```bash
# on the production server, by the security team
sudo install -d -m 700 -o root /etc/netmon/credentials
sudo install -m 600 -o root /dev/null /etc/netmon/credentials/db-password
sudoedit /etc/netmon/credentials/db-password       # paste the password, save
```

`deploy/netmon.service` contains `LoadCredential=netmon-db-password:/etc/netmon/credentials/db-password`.
NetMon refuses a password file that is readable by group or others.

The secrets database host must be an internal (private) address, or a name listed in
`secrets.allowed_hosts`. Use TLS to the database, for example `sslmode: verify-full` for PostgreSQL.

### Key rotation

Change the keys on the switches and in the database, then run `sudo systemctl restart netmon`.
NetMon reads the credentials again at start-up.
