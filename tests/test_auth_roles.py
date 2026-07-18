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


def test_configured_usernames_can_filter_by_role(monkeypatch):
    _users_env(monkeypatch, [
        {"username": "boss", "password_hash": auth.hash_password("a"), "role": "admin"},
        {"username": "watch", "password_hash": auth.hash_password("b"), "role": "viewer"},
    ])

    assert auth.configured_usernames() == ["boss", "watch"]
    assert auth.configured_usernames(auth.ROLE_ADMIN) == ["boss"]
    assert auth.configured_usernames(auth.ROLE_VIEWER) == ["watch"]


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
    assert "JSON list" in auth.configuration_error()


def test_invalid_role_is_a_configuration_error(monkeypatch):
    _users_env(monkeypatch, [
        {"username": "boss", "password_hash": auth.hash_password("a"), "role": "owner"},
    ])
    assert "admin or viewer" in auth.configuration_error()
    assert auth.is_auth_configured() is False


def test_duplicate_username_is_a_configuration_error(monkeypatch):
    password_hash = auth.hash_password("a")
    _users_env(monkeypatch, [
        {"username": "same", "password_hash": password_hash},
        {"username": "same", "password_hash": password_hash},
    ])
    assert "duplicate" in auth.configuration_error()


def test_register_viewer_persists_hashed_account(monkeypatch, tmp_path):
    monkeypatch.setenv(auth.SIGNUP_ENABLED_ENV, "true")
    monkeypatch.setenv(auth.AUTH_DB_PATH_ENV, str(tmp_path / "auth.db"))
    monkeypatch.delenv(auth.USERS_ENV, raising=False)
    monkeypatch.delenv(auth.PASSWORD_HASH_ENV, raising=False)

    created, message = auth.register_viewer("new.viewer", "StrongViewer#42")

    assert created is True
    assert "created" in message
    assert auth.authenticate("new.viewer", "StrongViewer#42") == auth.ROLE_VIEWER
    assert auth.authenticate("new.viewer", "StrongViewer#43") is None
    assert "StrongViewer#42" not in (tmp_path / "auth.db").read_bytes().decode(errors="ignore")


def test_register_viewer_never_allows_duplicate_configured_user(monkeypatch, tmp_path):
    monkeypatch.setenv(auth.SIGNUP_ENABLED_ENV, "true")
    monkeypatch.setenv(auth.AUTH_DB_PATH_ENV, str(tmp_path / "auth.db"))
    _users_env(monkeypatch, [
        {"username": "Admin", "password_hash": auth.hash_password("admin"), "role": "admin"},
    ])

    created, message = auth.register_viewer("admin", "StrongViewer#42")

    assert created is False
    assert "already" in message


def test_register_viewer_validates_password_and_feature_flag(monkeypatch, tmp_path):
    monkeypatch.setenv(auth.AUTH_DB_PATH_ENV, str(tmp_path / "auth.db"))
    monkeypatch.delenv(auth.SIGNUP_ENABLED_ENV, raising=False)
    assert auth.register_viewer("viewer.two", "StrongViewer#42")[0] is False

    monkeypatch.setenv(auth.SIGNUP_ENABLED_ENV, "true")
    assert auth.register_viewer("viewer.two", "weak")[0] is False
    assert auth.register_viewer("x", "StrongViewer#42")[0] is False
