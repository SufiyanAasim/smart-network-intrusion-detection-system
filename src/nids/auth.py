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
import os

_ALGORITHM = "pbkdf2_sha256"
_DEFAULT_ITERATIONS = 260_000
_SALT_BYTES = 16

USERNAME_ENV = "NIDS_AUTH_USERNAME"
PASSWORD_HASH_ENV = "NIDS_AUTH_PASSWORD_HASH"


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


def is_auth_configured():
    """True if a password hash is configured, i.e. the login gate is active."""
    return bool(os.environ.get(PASSWORD_HASH_ENV))


def configured_username():
    """The expected username (defaults to 'admin' if only a hash is set)."""
    return os.environ.get(USERNAME_ENV, "admin")


def check_credentials(username, password):
    """Verify a username/password pair against the configured credentials."""
    if not is_auth_configured():
        return True
    expected_user = configured_username()
    stored_hash = os.environ.get(PASSWORD_HASH_ENV, "")
    user_ok = hmac.compare_digest(username or "", expected_user)
    return user_ok and verify_password(password or "", stored_hash)


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
