"""Dashboard users, passwords and sessions.

* Passwords are hashed with scrypt (Python standard library), salted per user.
* The browser gets a random session token in an HttpOnly, SameSite=Strict cookie;
  only its SHA-256 is stored, so a copy of the database can't be used to log in.
* Repeated failed logins lock the username and the client address for a while.
* Two roles: admin (acknowledge alarms, poll now, remove links) and viewer (read only).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time

ROLES = ("admin", "viewer")
MIN_PASSWORD_LEN = 10
COOKIE = "netmon_session"
_N, _R, _P = 2 ** 14, 8, 1


class AuthError(Exception):
    pass


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                              dklen=len(bytes.fromhex(dk)))
        return hmac.compare_digest(calc, bytes.fromhex(dk))
    except (ValueError, TypeError):
        return False


_DUMMY_HASH = hash_password(secrets.token_hex(8))


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def check_password_policy(username: str, password: str):
    if len(password) < MIN_PASSWORD_LEN:
        raise AuthError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    if username.lower() in password.lower():
        raise AuthError("password must not contain the username")


class Auth:
    def __init__(self, db, cfg):
        self.db = db
        self.cfg = cfg                      # AuthCfg
        self._fails: dict[str, list[float]] = {}

    # ---------------------------------------------------------------- users
    def users(self) -> list[dict]:
        return self.db.query("SELECT username, role, created, last_login FROM users ORDER BY username")

    def has_users(self) -> bool:
        return bool(self.db.query("SELECT 1 FROM users LIMIT 1"))

    def add_user(self, username: str, password: str, role: str = "viewer"):
        username = username.strip()
        if not username or len(username) > 50 or not all(c.isalnum() or c in "._-" for c in username):
            raise AuthError("username: letters, digits, dot, dash and underscore only (max 50)")
        if role not in ROLES:
            raise AuthError(f"role must be one of {', '.join(ROLES)}")
        check_password_policy(username, password)
        if self.db.query("SELECT 1 FROM users WHERE username=?", (username,)):
            raise AuthError(f"user {username} already exists")
        self.db.execute("INSERT INTO users(username, pw_hash, role, created) VALUES (?,?,?,?)",
                        (username, hash_password(password), role, time.time()))

    def set_password(self, username: str, password: str):
        check_password_policy(username, password)
        if not self.db.query("SELECT 1 FROM users WHERE username=?", (username,)):
            raise AuthError(f"no user {username}")
        self.db.execute("UPDATE users SET pw_hash=? WHERE username=?", (hash_password(password), username))
        self.db.execute("DELETE FROM sessions WHERE username=?", (username,))   # log out everywhere

    def set_role(self, username: str, role: str):
        if role not in ROLES:
            raise AuthError(f"role must be one of {', '.join(ROLES)}")
        self.db.execute("UPDATE users SET role=? WHERE username=?", (role, username))

    def delete_user(self, username: str):
        self.db.execute("DELETE FROM sessions WHERE username=?", (username,))
        self.db.execute("DELETE FROM users WHERE username=?", (username,))

    # ---------------------------------------------------------------- lock-out
    def _locked(self, key: str) -> bool:
        window = self.cfg.lockout_minutes * 60
        now = time.time()
        fails = [t for t in self._fails.get(key, []) if now - t < window]
        self._fails[key] = fails
        return len(fails) >= self.cfg.max_failures

    def is_locked(self, username: str, client: str) -> bool:
        return self._locked(f"u:{username.lower()}") or self._locked(f"c:{client}")

    def _fail(self, username: str, client: str):
        now = time.time()
        for k in (f"u:{username.lower()}", f"c:{client}"):
            self._fails.setdefault(k, []).append(now)

    # ---------------------------------------------------------------- sessions
    def login(self, username: str, password: str, client: str = "") -> str | None:
        """Returns a session token, or None. Takes the same time whether or not the user exists."""
        if self.is_locked(username, client):
            raise AuthError("too many failed logins; try again later")
        rows = self.db.query("SELECT pw_hash FROM users WHERE username=?", (username,))
        ok = verify_password(password, rows[0]["pw_hash"] if rows else _DUMMY_HASH) and bool(rows)
        if not ok:
            self._fail(username, client)
            return None
        self._fails.pop(f"u:{username.lower()}", None)
        token = secrets.token_urlsafe(32)
        expires = time.time() + self.cfg.session_hours * 3600
        self.db.execute("INSERT INTO sessions(token_hash, username, expires) VALUES (?,?,?)",
                        (_token_hash(token), username, expires))
        self.db.execute("UPDATE users SET last_login=? WHERE username=?", (time.time(), username))
        self.db.execute("DELETE FROM sessions WHERE expires < ?", (time.time(),))
        return token

    def session(self, token: str | None) -> dict | None:
        if not token:
            return None
        rows = self.db.query(
            "SELECT s.username, u.role, s.expires FROM sessions s JOIN users u ON u.username = s.username "
            "WHERE s.token_hash=?", (_token_hash(token),))
        if not rows or rows[0]["expires"] < time.time():
            return None
        return {"username": rows[0]["username"], "role": rows[0]["role"]}

    def logout(self, token: str | None):
        if token:
            self.db.execute("DELETE FROM sessions WHERE token_hash=?", (_token_hash(token),))
