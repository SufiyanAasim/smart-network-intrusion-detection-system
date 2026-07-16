"""Optional password gate for the dashboard.

Security notes:
- Passwords are never stored or compared in plaintext. A deployment stores a
  PBKDF2-SHA256 hash string in the NIDS_AUTH_PASSWORD_HASH environment
  variable; the plaintext password only ever lives momentarily in the login
  form's memory during verification.
- Generate a hash with `python -m nids.auth` (prompts for a password and
  prints the hash to paste into `.env`) — the password is read via getpass,
  not echoed or logged.
- If NIDS_AUTH_PASSWORD_HASH is unset, auth is disabled and the app runs
  open (backward compatible with earlier versions).

Kept free of Streamlit imports so it can be unit tested directly.
"""

import hashlib
import hmac
import json
import os

_ALGORITHM = "pbkdf2_sha256"
_DEFAULT_ITERATIONS = 260_000
_SALT_BYTES = 16

USERNAME_ENV = "NIDS_AUTH_USERNAME"
PASSWORD_HASH_ENV = "NIDS_AUTH_PASSWORD_HASH"
# Multi-user config: a JSON list of {"username","password_hash","role"} where
# role is "admin" or "viewer". Takes precedence over the single-user vars.
USERS_ENV = "NIDS_AUTH_USERS"

ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"


def hash_password(password, iterations=_DEFAULT_ITERATIONS, salt=None):
    """Return a self-describing PBKDF2-SHA256 hash string for `password`.

    Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>. A random salt is
    generated when not supplied (supply one only for deterministic tests).
    """
    if salt is None:
        salt = os.urandom(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{_ALGORITHM}${iterations}${salt.hex()}${derived.hex()}"


def verify_password(password, stored_hash):
    """Constant-time check of `password` against a stored hash string.

    Returns False (never raises) on any malformed/unrecognized hash.
    """
    if not stored_hash:
        return False
    try:
        algorithm, iterations, salt_hex, hash_hex = stored_hash.split("$")
        if algorithm != _ALGORITHM:
            return False
        derived = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(derived.hex(), hash_hex)


def _load_users():
    """Return the configured user list [{username, password_hash, role}, ...].

    Prefers the multi-user NIDS_AUTH_USERS JSON; falls back to the
    single-user NIDS_AUTH_USERNAME/NIDS_AUTH_PASSWORD_HASH pair (treated as an
    admin). Returns [] when nothing is configured.
    """
    raw = os.environ.get(USERS_ENV)
    if raw:
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
        return result

    single_hash = os.environ.get(PASSWORD_HASH_ENV)
    if single_hash:
        return [{
            "username": os.environ.get(USERNAME_ENV, "admin"),
            "password_hash": single_hash,
            "role": ROLE_ADMIN,
        }]
    return []


def is_auth_configured():
    """True if any user is configured, i.e. the login gate is active."""
    return bool(_load_users())


def configured_username():
    """The first configured username (for display when a single user is set)."""
    users = _load_users()
    return users[0]["username"] if users else "admin"


def authenticate(username, password):
    """Return the matching user's role on success, else None.

    Iterates all configured users; comparison of the username is
    constant-time and the password is verified against that user's hash.
    """
    for user in _load_users():
        if hmac.compare_digest(username or "", user["username"]):
            if verify_password(password or "", user["password_hash"]):
                return user.get("role", ROLE_VIEWER)
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
    if pwd != confirm:
        print("Passwords did not match.")
        return
    print("\nAdd this line to your .env (keep it secret):\n")
    print(f"{PASSWORD_HASH_ENV}={hash_password(pwd)}")


if __name__ == "__main__":  # pragma: no cover
    _cli()
