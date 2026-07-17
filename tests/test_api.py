import pandas as pd

from nids import api, storage


def _seed(db_path):
    df = pd.DataFrame([
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.9", "protocol_type": "tcp",
         "service": "http", "flag": "S0", "src_bytes": 40, "count": 5,
         "serror_rate": 1.0, "RF Analysis": "Attack", "DT Analysis": "Attack",
         "Anomaly Analysis": "Attack", "Triage": "Critical", "Risk Score": 100},
        {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.9", "protocol_type": "tcp",
         "service": "http", "flag": "SF", "src_bytes": 120, "count": 1,
         "serror_rate": 0.0, "RF Analysis": "Normal", "DT Analysis": "Normal",
         "Anomaly Analysis": "Normal", "Triage": "Clear", "Risk Score": 0},
    ])
    storage.save_detections(df, source="upload", db_path=db_path)


def test_health_route():
    status, body = api.route("/health")
    assert status == 200
    assert body["status"] == "ok"


def test_summary_route(tmp_path):
    db = str(tmp_path / "history.db")
    _seed(db)
    status, body = api.route("/api/summary", db_path=db)
    assert status == 200
    assert body["total"] == 2
    assert body["rf_attacks"] == 1
    assert body["critical_triage"] == 1
    assert body["avg_risk_score"] == 50.0


def test_detections_route_with_limit(tmp_path):
    db = str(tmp_path / "history.db")
    _seed(db)
    status, body = api.route("/api/detections", {"limit": ["1"]}, db_path=db)
    assert status == 200
    assert body["count"] == 1


def test_triage_route_filters_by_consensus_risk(tmp_path):
    db = str(tmp_path / "history.db")
    _seed(db)
    status, body = api.route(
        "/api/triage", {"min_risk": ["60"], "limit": ["10"]}, db_path=db
    )
    assert status == 200
    assert body["count"] == 1
    assert body["detections"][0]["risk_score"] == 100


def test_triage_route_validates_min_risk(tmp_path):
    db = str(tmp_path / "history.db")
    _seed(db)
    assert api.route("/api/triage", {"min_risk": ["bad"]}, db_path=db)[0] == 400
    assert api.route("/api/triage", {"min_risk": ["101"]}, db_path=db)[0] == 400


def test_ip_route(tmp_path):
    db = str(tmp_path / "history.db")
    _seed(db)
    status, body = api.route("/api/ip/10.0.0.1", db_path=db)
    assert status == 200
    assert body["ip"] == "10.0.0.1"
    assert body["total"] == 1
    assert body["rf_attacks"] == 1


def test_unknown_route_404():
    status, body = api.route("/nope")
    assert status == 404


def test_bad_limit_is_400_not_500(tmp_path):
    db = str(tmp_path / "history.db")
    _seed(db)
    status, body = api.route("/api/detections", {"limit": ["abc"]}, db_path=db)
    assert status == 400
    assert "limit" in body["error"]


def test_out_of_range_limit_is_400(tmp_path):
    db = str(tmp_path / "history.db")
    _seed(db)
    assert api.route("/api/detections", {"limit": ["0"]}, db_path=db)[0] == 400
    assert api.route("/api/detections", {"limit": ["999999"]}, db_path=db)[0] == 400


def test_ip_route_percent_decodes(tmp_path):
    db = str(tmp_path / "history.db")
    _seed(db)
    status, body = api.route("/api/ip/10.0.0.1", db_path=db)
    assert status == 200 and body["ip"] == "10.0.0.1"


def test_empty_ip_is_400(tmp_path):
    db = str(tmp_path / "history.db")
    _seed(db)
    assert api.route("/api/ip/", db_path=db)[0] == 400


def test_token_auth_enforced(monkeypatch):
    monkeypatch.setenv(api.TOKEN_ENV, "secret")
    status, _ = api.route("/health", auth_header=None)
    assert status == 401
    status, _ = api.route("/health", auth_header="Bearer secret")
    assert status == 200
    status, _ = api.route("/health", auth_header="Bearer wrong")
    assert status == 401
    status, _ = api.route("/health", auth_header="bearer secret")
    assert status == 200


def test_token_auth_open_when_unset(monkeypatch):
    monkeypatch.delenv(api.TOKEN_ENV, raising=False)
    status, _ = api.route("/health")
    assert status == 200
