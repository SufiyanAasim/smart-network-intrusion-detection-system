"""Encrypted backup of the detection history database.

Provides an at-rest encryption *option* for `data/history.db`: the operator
can download an encrypted backup and restore it later. Encryption uses
Fernet (AES-128-CBC + HMAC-SHA256) from the `cryptography` package, with a
key supplied via the NIDS_DB_ENCRYPTION_KEY environment variable.

`cryptography` is imported lazily so the rest of the app still works if it
isn't installed — callers should treat a None/False return as "encryption
unavailable".

Kept free of Streamlit imports so it can be unit tested directly.
"""

import os

KEY_ENV = "NIDS_DB_ENCRYPTION_KEY"


def encryption_available():
    """True if the cryptography package is importable."""
    try:
        import cryptography.fernet  # noqa: F401
    except ImportError:
        return False
    return True


def generate_key():
    """Return a new base64 Fernet key (str), or None if crypto unavailable."""
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None
    return Fernet.generate_key().decode("ascii")


def configured_key():
    """Return the configured key bytes, or None if unset."""
    key = os.environ.get(KEY_ENV)
    return key.encode("ascii") if key else None


def encrypt_bytes(data, key=None):
    """Encrypt bytes with Fernet. Returns token bytes, or None if unavailable.

    `key` (base64 str/bytes) defaults to NIDS_DB_ENCRYPTION_KEY.
    """
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None
    key_bytes = _coerce_key(key)
    if key_bytes is None:
        return None
    return Fernet(key_bytes).encrypt(data)


def decrypt_bytes(token, key=None):
    """Decrypt a Fernet token back to bytes.

    Raises ValueError on an invalid key/token so callers can surface a clear
    "wrong key or corrupt backup" message.
    """
    try:
        from cryptography.fernet import Fernet, InvalidToken
    except ImportError as exc:  # pragma: no cover - exercised only without cryptography
        raise RuntimeError("cryptography is not installed") from exc
    key_bytes = _coerce_key(key)
    if key_bytes is None:
        raise ValueError("No encryption key configured")
    try:
        return Fernet(key_bytes).decrypt(token)
    except InvalidToken as exc:
        raise ValueError("Invalid key or corrupt backup") from exc


def encrypt_file(path, key=None):
    """Read a file and return its encrypted bytes (or None if unavailable)."""
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return encrypt_bytes(f.read(), key=key)


def _coerce_key(key):
    if key is None:
        return configured_key()
    if isinstance(key, str):
        return key.encode("ascii")
    return key
