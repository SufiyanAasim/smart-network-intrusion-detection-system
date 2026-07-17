"""Optional password gate for the dashboard.

Security notes:
- Passwords are never stored or compared in plaintext. A deployment stores a
  PBKDF2-SHA256 hash string in the NIDS_AUTH_PASSWORD_HASH environment
  variable; the plaintext password only ever lives momentarily in the login
  form's memory during verification.
- Generate a hash with `python src/nids/auth.py` (prompts for a password and
  prints the hash to paste into `.env`) — the password is read via getpass,
  not echoed or logged.
- If NIDS_AUTH_PASSWORD_HASH is unset, auth is disabled and the app runs
  open (backward compatible with earlier versions).

Kept free of Streamlit imports so it can be unit tested directly.
"""

import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import time

_ALGORITHM = "pbkdf2_sha256"
_DEFAULT_ITERATIONS = 260_000
_MIN_ITERATIONS = 100_000
_MAX_ITERATIONS = 2_000_000
_SALT_BYTES = 16

USERNAME_ENV = "NIDS_AUTH_USERNAME"
PASSWORD_HASH_ENV = "NIDS_AUTH_PASSWORD_HASH"
# Multi-user config: a JSON list of {"username","password_hash","role"} where
# role is "admin" or "viewer". Takes precedence over the single-user vars.
USERS_ENV = "NIDS_AUTH_USERS"
SIGNUP_ENABLED_ENV = "NIDS_SIGNUP_ENABLED"
AUTH_DB_PATH_ENV = "NIDS_AUTH_DB_PATH"

ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"

_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def signup_enabled():
    """True only when local self-registration is explicitly enabled."""
    return os.environ.get(SIGNUP_ENABLED_ENV, "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def auth_db_path():
    """Return the persistent database used for locally registered accounts."""
    return os.environ.get(AUTH_DB_PATH_ENV, os.path.join("data", "auth.db"))


def _connect_auth_db():
    path = os.path.abspath(auth_db_path())
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS local_users (
            username TEXT PRIMARY KEY COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
            created_at INTEGER NOT NULL
        )
        """
    )
    return connection


def _load_registered_users():
    """Load self-registered users; a missing/unreadable DB is safely empty."""
    path = os.path.abspath(auth_db_path())
    if not os.path.exists(path):
        return []
    try:
        with _connect_auth_db() as connection:
            rows = connection.execute(
                "SELECT username, password_hash, role FROM local_users"
            ).fetchall()
    except (OSError, sqlite3.Error):
        return []
    return [
        {"username": username, "password_hash": password_hash, "role": role}
        for username, password_hash, role in rows
    ]


def validate_signup(username, password):
    """Return a user-facing validation error, or ``None`` when valid."""
    username = (username or "").strip()
    if not _USERNAME_PATTERN.fullmatch(username):
        return "Username must be 3–32 characters using letters, numbers, dot, dash, or underscore."
    if len(password or "") < 12:
        return "Password must contain at least 12 characters."
    checks = (
        any(char.islower() for char in password),
        any(char.isupper() for char in password),
        any(char.isdigit() for char in password),
        any(not char.isalnum() for char in password),
    )
    if not all(checks):
        return "Password must include uppercase, lowercase, number, and symbol characters."
    return None


def register_viewer(username, password):
    """Persist a new self-service Viewer account.

    Administrator accounts deliberately remain configuration-managed so an
    unauthenticated visitor can never promote themselves through the UI.
    Returns ``(created, message)``.
    """
    if not signup_enabled():
        return False, "Account creation is disabled by the administrator."
    username = (username or "").strip()
    validation_error = validate_signup(username, password)
    if validation_error:
        return False, validation_error

    configured_names = {u["username"].casefold() for u in _load_users(include_registered=False)}
    if username.casefold() in configured_names:
        return False, "That username is already in use."
    try:
        with _connect_auth_db() as connection:
            connection.execute(
                "INSERT INTO local_users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username, hash_password(password), ROLE_VIEWER, int(time.time())),
            )
    except sqlite3.IntegrityError:
        return False, "That username is already in use."
    except (OSError, sqlite3.Error):
        return False, "The account store is unavailable. Ask the administrator to check its path."
    return True, "Viewer account created. You can now sign in."


def hash_password(password, iterations=_DEFAULT_ITERATIONS, salt=None):
    """Return a self-describing PBKDF2-SHA256 hash string for `password`.

    Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>. A random salt is
    generated when not supplied (supply one only for deterministic tests).
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if not password:
        raise ValueError("password must not be empty")
    iteration_count = int(iterations)
    if not _MIN_ITERATIONS <= iteration_count <= _MAX_ITERATIONS:
        raise ValueError("PBKDF2 iterations are outside the supported range")
    if salt is None:
        salt = os.urandom(_SALT_BYTES)
    if not isinstance(salt, bytes) or len(salt) != _SALT_BYTES:
        raise ValueError(f"salt must be exactly {_SALT_BYTES} bytes")
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iteration_count)
    return f"{_ALGORITHM}${iteration_count}${salt.hex()}${derived.hex()}"


def verify_password(password, stored_hash):
    """Constant-time check of `password` against a stored hash string.

    Returns False (never raises) on any malformed/unrecognized hash.
    """
    if not isinstance(password, str) or not stored_hash:
        return False
    try:
        algorithm, iterations, salt_hex, hash_hex = stored_hash.split("$")
        if algorithm != _ALGORITHM:
            return False
        iteration_count = int(iterations)
        if not _MIN_ITERATIONS <= iteration_count <= _MAX_ITERATIONS:
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        if len(salt) != _SALT_BYTES or len(expected) != hashlib.sha256().digest_size:
            return False
        derived = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iteration_count
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(derived, expected)


def configuration_error():
    """Return a safe validation message for invalid auth config, else None."""
    raw = os.environ.get(USERS_ENV)
    if not raw:
        return None
    try:
        users = json.loads(raw)
    except (ValueError, TypeError):
        return f"{USERS_ENV} must be a JSON list of users"
    if not isinstance(users, list) or not users:
        return f"{USERS_ENV} must be a non-empty JSON list"

    seen = set()
    for index, user in enumerate(users, start=1):
        if not isinstance(user, dict):
            return f"{USERS_ENV} user #{index} must be an object"
        username = user.get("username")
        password_hash = user.get("password_hash")
        role = user.get("role", ROLE_VIEWER)
        if not isinstance(username, str) or not username.strip():
            return f"{USERS_ENV} user #{index} has an invalid username"
        if username in seen:
            return f"{USERS_ENV} contains duplicate username {username!r}"
        if not isinstance(password_hash, str) or not password_hash:
            return f"{USERS_ENV} user #{index} has an invalid password_hash"
        if role not in (ROLE_ADMIN, ROLE_VIEWER):
            return f"{USERS_ENV} user #{index} role must be admin or viewer"
        seen.add(username)
    return None


def _load_users(include_registered=True):
    """Return the configured user list [{username, password_hash, role}, ...].

    Prefers the multi-user NIDS_AUTH_USERS JSON; falls back to the
    single-user NIDS_AUTH_USERNAME/NIDS_AUTH_PASSWORD_HASH pair (treated as an
    admin). Returns [] when nothing is configured.
    """
    raw = os.environ.get(USERS_ENV)
    if raw:
        if configuration_error() is not None:
            return []
        try:
            users = json.loads(raw)
        except (ValueError, TypeError):
            return []
        result = []
        for u in users:
            if not isinstance(u, dict) or "username" not in u or "password_hash" not in u:
                continue
            result.append({
                "username": u["username"],
                "password_hash": u["password_hash"],
                "role": u.get("role", ROLE_VIEWER),
            })
        return result + (_load_registered_users() if include_registered else [])

    single_hash = os.environ.get(PASSWORD_HASH_ENV)
    if single_hash:
        result = [{
            "username": os.environ.get(USERNAME_ENV, "admin"),
            "password_hash": single_hash,
            "role": ROLE_ADMIN,
        }]
        return result + (_load_registered_users() if include_registered else [])
    return _load_registered_users() if include_registered else []


def is_auth_configured():
    """True if any user is configured, i.e. the login gate is active."""
    return bool(_load_users())


def configured_username():
    """The first configured username (for display when a single user is set)."""
    users = _load_users()
    return users[0]["username"] if users else "admin"


def configured_usernames(role=None):
    """Return configured usernames, optionally limited to one access role.

    Password hashes are deliberately excluded so the UI can preselect a local
    account without exposing credential material.
    """
    return [
        user["username"]
        for user in _load_users()
        if role is None or user.get("role", ROLE_VIEWER) == role
    ]


_failed_attempts = {}
_lockouts = {}

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 300  # 5 minutes


def is_locked_out(username):
    """Return (locked_out: bool, remaining_seconds: int)."""
    if not username:
        return False, 0
    now = time.time()
    until = _lockouts.get(username, 0.0)
    if until > now:
        return True, math.ceil(until - now)
    return False, 0


def authenticate(username, password):
    """Return the matching user's role on success, else None.

    Enforces brute-force lockout protection.
    """
    if not username:
        return None

    locked, remaining = is_locked_out(username)
    if locked:
        return None

    for user in _load_users():
        if hmac.compare_digest(username, user["username"]):
            if verify_password(password or "", user["password_hash"]):
                # Success: reset rate limiting for this user
                _failed_attempts.pop(username, None)
                _lockouts.pop(username, None)
                return user.get("role", ROLE_VIEWER)

    # Failure: record attempt for rate limiting
    now = time.time()
    attempts = _failed_attempts.setdefault(username, [])
    # Keep only failed attempts from the last 10 minutes
    attempts = [t for t in attempts if now - t < 600]
    attempts.append(now)
    _failed_attempts[username] = attempts

    if len(attempts) >= MAX_FAILED_ATTEMPTS:
        _lockouts[username] = now + LOCKOUT_DURATION_SECONDS
        _failed_attempts[username] = []

    return None


def check_credentials(username, password):
    """Backward-compatible boolean check (open when unconfigured)."""
    if not is_auth_configured():
        return True
    return authenticate(username, password) is not None


def is_admin(role):
    """True if the given role may perform admin-only actions.

    When auth is disabled entirely, everyone is treated as admin so the app
    keeps its full single-user behavior.
    """
    if not is_auth_configured():
        return True
    return role == ROLE_ADMIN


def _cli():  # pragma: no cover - interactive helper
    import getpass

    pwd = getpass.getpass("New dashboard password: ")
    confirm = getpass.getpass("Confirm password: ")
    if not pwd:
        print("Password must not be empty.")
        return
    if pwd != confirm:
        print("Passwords did not match.")
        return
    print("\nAdd this line to your .env (keep it secret):\n")
    print(f"{PASSWORD_HASH_ENV}={hash_password(pwd)}")


if __name__ == "__main__":  # pragma: no cover
    _cli()
