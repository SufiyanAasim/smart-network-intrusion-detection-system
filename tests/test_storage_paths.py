"""Regression tests for how the history-database path is resolved.

The packaged desktop build stores history under a per-user directory that can
live on a different drive from the app bundle, which is what NIDS_DB_PATH is
for. These pin the behaviour the app depends on.
"""

import importlib
import os

import pytest


def _reload_storage():
    from nids import storage
    return importlib.reload(storage)


def test_db_path_defaults_into_the_repo(monkeypatch):
    monkeypatch.delenv("NIDS_DB_PATH", raising=False)
    storage = _reload_storage()
    assert storage.DEFAULT_DB_PATH.endswith(os.path.join("data", "history.db"))


def test_db_path_honours_env_override(monkeypatch, tmp_path):
    override = str(tmp_path / "elsewhere" / "history.db")
    monkeypatch.setenv("NIDS_DB_PATH", override)
    storage = _reload_storage()
    assert storage.DEFAULT_DB_PATH == override


def test_db_path_override_is_usable(monkeypatch, tmp_path):
    """An overridden path must be created and written to on demand."""
    import pandas as pd

    override = str(tmp_path / "nested" / "dir" / "history.db")
    monkeypatch.setenv("NIDS_DB_PATH", override)
    storage = _reload_storage()

    storage.save_detections(
        pd.DataFrame([{
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.9", "protocol_type": "tcp",
            "service": "http", "flag": "S0", "src_bytes": 40, "count": 1,
            "serror_rate": 0.0, "RF Analysis": "🚨 ATTACK", "DT Analysis": "✅ Normal",
        }]),
        source="live",
    )
    assert os.path.exists(override)
    assert storage.query_summary()["total"] == 1


def test_relpath_across_drives_is_guarded():
    """The History tab labels the DB with os.path.relpath, which raises on
    Windows when the DB and the app are on different drives (the packaged
    build's real layout). Callers must tolerate that."""
    if os.name != "nt":
        pytest.skip("cross-drive relpath only raises on Windows")
    with pytest.raises(ValueError):
        os.path.relpath(r"C:\Users\x\NIDS\history.db", r"D:\app")


def teardown_module():
    # Leave the module in its default state for the rest of the suite.
    os.environ.pop("NIDS_DB_PATH", None)
    _reload_storage()
