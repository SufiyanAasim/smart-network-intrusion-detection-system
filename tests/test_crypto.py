import pytest

from nids import crypto

pytest.importorskip("cryptography")


def test_encrypt_decrypt_roundtrip():
    key = crypto.generate_key()
    token = crypto.encrypt_bytes(b"secret data", key=key)
    assert token is not None
    assert token != b"secret data"
    assert crypto.decrypt_bytes(token, key=key) == b"secret data"


def test_decrypt_with_wrong_key_raises():
    key1 = crypto.generate_key()
    key2 = crypto.generate_key()
    token = crypto.encrypt_bytes(b"data", key=key1)
    with pytest.raises(ValueError):
        crypto.decrypt_bytes(token, key=key2)


def test_encrypt_bytes_none_without_key(monkeypatch):
    monkeypatch.delenv(crypto.KEY_ENV, raising=False)
    assert crypto.encrypt_bytes(b"data") is None


def test_encrypt_file_roundtrip(tmp_path):
    key = crypto.generate_key()
    path = tmp_path / "db.sqlite"
    path.write_bytes(b"fake-db-bytes")
    token = crypto.encrypt_file(str(path), key=key)
    assert crypto.decrypt_bytes(token, key=key) == b"fake-db-bytes"


def test_encryption_available():
    assert crypto.encryption_available() is True
