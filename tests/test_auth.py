from nids import auth


def test_hash_and_verify_roundtrip():
    stored = auth.hash_password("s3cret!")
    assert auth.verify_password("s3cret!", stored) is True
    assert auth.verify_password("wrong", stored) is False


def test_hash_is_not_plaintext():
    stored = auth.hash_password("s3cret!")
    assert "s3cret!" not in stored
    assert stored.startswith("pbkdf2_sha256$")


def test_hash_uses_random_salt():
    assert auth.hash_password("same") != auth.hash_password("same")


def test_hash_accepts_numeric_iteration_string_and_validates_salt():
    stored = auth.hash_password("same", iterations="260000", salt=b"a" * 16)
    assert auth.verify_password("same", stored) is True


def test_hash_rejects_empty_password():
    import pytest

    with pytest.raises(ValueError, match="empty"):
        auth.hash_password("")


def test_verify_password_rejects_malformed_hash():
    assert auth.verify_password("x", "") is False
    assert auth.verify_password("x", "not-a-valid-hash") is False
    assert auth.verify_password("x", "md5$1$aa$bb") is False
    assert auth.verify_password("x", "pbkdf2_sha256$999999999$" + "aa" * 16 + "$" + "bb" * 32) is False


def test_is_auth_configured(monkeypatch):
    monkeypatch.delenv(auth.PASSWORD_HASH_ENV, raising=False)
    assert auth.is_auth_configured() is False
    monkeypatch.setenv(auth.PASSWORD_HASH_ENV, auth.hash_password("p"))
    assert auth.is_auth_configured() is True


def test_check_credentials_open_when_unconfigured(monkeypatch):
    monkeypatch.delenv(auth.PASSWORD_HASH_ENV, raising=False)
    assert auth.check_credentials("anyone", "anything") is True


def test_check_credentials_enforced_when_configured(monkeypatch):
    monkeypatch.setenv(auth.USERNAME_ENV, "operator")
    monkeypatch.setenv(auth.PASSWORD_HASH_ENV, auth.hash_password("hunter2"))

    assert auth.check_credentials("operator", "hunter2") is True
    assert auth.check_credentials("operator", "bad") is False
    assert auth.check_credentials("intruder", "hunter2") is False
