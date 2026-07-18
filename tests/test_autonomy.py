from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pandas as pd

from nids import autonomy


NOW = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)


def evidence(ip="8.8.8.8", risks=(100, 100, 100)):
    return pd.DataFrame({
        "src_ip": [ip] * len(risks),
        "dst_ip": ["192.0.2.10"] * len(risks),
        "protocol_type": ["tcp"] * len(risks),
        "Risk Score": list(risks),
    })


def policy(**overrides):
    values = {
        "mode": autonomy.MODE_SHADOW,
        "min_risk": 90,
        "min_events": 3,
        "correlation_window_seconds": 300,
        "block_ttl_minutes": 30,
        "max_active_blocks": 5,
        "execution_enabled": False,
        "allow_private_sources": False,
    }
    values.update(overrides)
    return autonomy.Policy(**values)


def ok_runner(command, **kwargs):
    return SimpleNamespace(returncode=0, stdout="ok", stderr="", command=command)


def test_shadow_correlation_is_simulated_and_stable():
    decisions = autonomy.correlate_batch(
        evidence(), "live", policy=policy(), now=NOW
    )
    assert len(decisions) == 1
    assert decisions[0]["status"] == "simulated"
    assert decisions[0]["eligible"] is True
    assert decisions[0]["event_count"] == 3
    assert decisions[0]["incident_id"] == autonomy.correlate_batch(
        evidence(), "live", policy=policy(), now=NOW
    )[0]["incident_id"]


def test_private_source_is_protected_by_default():
    decision = autonomy.correlate_batch(
        evidence("192.168.1.20"), "live", policy=policy(), now=NOW
    )[0]
    assert decision["status"] == "protected_source"
    assert decision["eligible"] is False


def test_approval_records_pending_action_and_denial(tmp_path):
    db = str(tmp_path / "history.db")
    p = policy(mode=autonomy.MODE_APPROVAL)
    autonomy.record_batch(evidence(), "upload", mode=autonomy.MODE_APPROVAL,
                          policy=p, db_path=db, now=NOW)
    actions = autonomy.query_actions(db_path=db)
    assert actions.iloc[0]["status"] == "pending"
    ok, message = autonomy.decide_action(
        int(actions.iloc[0]["id"]), "deny", "admin", policy=p, db_path=db
    )
    assert ok and message == "action denied"
    assert autonomy.query_actions(db_path=db).iloc[0]["status"] == "denied"


def test_approval_cannot_bypass_disabled_server_execution(tmp_path):
    db = str(tmp_path / "history.db")
    p = policy(mode=autonomy.MODE_APPROVAL, execution_enabled=False)
    autonomy.record_batch(evidence(), "upload", mode=autonomy.MODE_APPROVAL,
                          policy=p, db_path=db, now=NOW)
    action_id = int(autonomy.query_actions(db_path=db).iloc[0]["id"])
    ok, message = autonomy.decide_action(
        action_id, "approve", "admin", policy=p, db_path=db
    )
    assert ok is True
    assert "guarded" in message
    assert autonomy.query_actions(db_path=db).iloc[0]["status"] == "guarded"


def test_autonomous_action_executes_and_rolls_back(tmp_path):
    db = str(tmp_path / "history.db")
    p = policy(
        mode=autonomy.MODE_AUTONOMOUS, execution_enabled=True,
        block_ttl_minutes=10,
    )
    autonomy.record_batch(
        evidence(), "live", mode=autonomy.MODE_AUTONOMOUS, actor="engine",
        policy=p, db_path=db, now=NOW, runner=ok_runner,
    )
    action = autonomy.query_actions(db_path=db).iloc[0]
    assert action["status"] == "active"
    assert action["expires_at"] is not None
    results = autonomy.expire_actions(
        db_path=db, runner=ok_runner, now=NOW + timedelta(minutes=11)
    )
    assert results == [(True, "block rolled back")]
    assert autonomy.query_actions(db_path=db).iloc[0]["status"] == "rolled_back"


def test_execution_is_guarded_when_disabled(tmp_path):
    db = str(tmp_path / "history.db")
    p = policy(mode=autonomy.MODE_AUTONOMOUS, execution_enabled=False)
    autonomy.record_batch(evidence(), "live", mode=autonomy.MODE_AUTONOMOUS,
                          policy=p, db_path=db, now=NOW)
    action = autonomy.query_actions(db_path=db).iloc[0]
    assert action["status"] == "guarded"


def test_drift_report_recommends_review_for_large_shift():
    baseline = pd.DataFrame({
        "risk_score": [5] * 100,
        "src_bytes": [100] * 100,
        "count": [2] * 100,
        "serror_rate": [0.0] * 100,
    })
    recent = pd.DataFrame({
        "risk_score": [100] * 50,
        "src_bytes": [10000] * 50,
        "count": [90] * 50,
        "serror_rate": [1.0] * 50,
    })
    report = autonomy.drift_report(pd.concat([recent, baseline], ignore_index=True))
    assert report["status"] == "drift"
    assert report["retrain_recommended"] is True
