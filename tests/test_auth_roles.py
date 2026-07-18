import json

from nids import auth


def _users_env(monkeypatch, users):
    monkeypatch.delenv(auth.PASSWORD_HASH_ENV, raising=False)
    monkeypatch.setenv(auth.USERS_ENV, json.dumps(users))


def test_multi_user_authenticate_returns_role(monkeypatch):
    _users_env(monkeypatch, [
        {"username": "boss", "password_hash": auth.hash_password("a"), "role": "admin"},
        {"username": "watch", "password_hash": auth.hash_password("b"), "role": "viewer"},
    ])

    assert auth.authenticate("boss", "a") == "admin"
    assert auth.authenticate("watch", "b") == "viewer"
    assert auth.authenticate("boss", "wrong") is None
    assert auth.authenticate("ghost", "a") is None


def test_is_admin_by_role(monkeypatch):
    _users_env(monkeypatch, [
        {"username": "boss", "password_hash": auth.hash_password("a"), "role": "admin"},
    ])
    assert auth.is_admin("admin") is True
    assert auth.is_admin("viewer") is False


def test_is_admin_true_when_auth_disabled(monkeypatch):
    monkeypatch.delenv(auth.USERS_ENV, raising=False)
    monkeypatch.delenv(auth.PASSWORD_HASH_ENV, raising=False)
    assert auth.is_admin("viewer") is True  # open app = full access


def test_single_user_still_works_as_admin(monkeypatch):
    monkeypatch.delenv(auth.USERS_ENV, raising=False)
    monkeypatch.setenv(auth.USERNAME_ENV, "solo")
    monkeypatch.setenv(auth.PASSWORD_HASH_ENV, auth.hash_password("pw"))

    assert auth.authenticate("solo", "pw") == "admin"
    assert auth.check_credentials("solo", "pw") is True


def test_malformed_users_json_disables_auth(monkeypatch):
    monkeypatch.delenv(auth.PASSWORD_HASH_ENV, raising=False)
    monkeypatch.setenv(auth.USERS_ENV, "not-json")
    assert auth.is_auth_configured() is False
