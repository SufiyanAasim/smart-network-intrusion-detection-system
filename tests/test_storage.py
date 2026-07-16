import pandas as pd

from nids import storage


def _sample_df():
    return pd.DataFrame(
        [
            {
                "src_ip": "10.0.0.1", "dst_ip": "10.0.0.9", "protocol_type": "tcp",
                "service": "http", "flag": "S0", "src_bytes": 40, "count": 5,
                "serror_rate": 1.0, "RF Analysis": "🚨 ATTACK", "DT Analysis": "✅ Normal",
            },
            {
                "src_ip": "10.0.0.2", "dst_ip": "10.0.0.9", "protocol_type": "tcp",
                "service": "http", "flag": "SF", "src_bytes": 120, "count": 1,
                "serror_rate": 0.0, "RF Analysis": "✅ Normal", "DT Analysis": "✅ Normal",
            },
        ]
    )


def test_save_and_query_recent_roundtrip(tmp_path):
    db_path = tmp_path / "history.db"

    storage.save_detections(_sample_df(), source="live", db_path=str(db_path))
    recent = storage.query_recent(limit=10, db_path=str(db_path))

    assert len(recent) == 2
    assert set(recent["source"]) == {"live"}


def test_save_detections_empty_df_is_a_noop(tmp_path):
    db_path = tmp_path / "history.db"

    storage.save_detections(pd.DataFrame(), source="live", db_path=str(db_path))

    assert not db_path.exists()


def test_query_summary_counts_attacks_per_model(tmp_path):
    db_path = tmp_path / "history.db"
    storage.save_detections(_sample_df(), source="upload", db_path=str(db_path))

    summary = storage.query_summary(db_path=str(db_path))

    assert summary["total"] == 2
    assert summary["rf_attacks"] == 1
    assert summary["dt_attacks"] == 0


def test_query_recent_filters_by_source(tmp_path):
    db_path = tmp_path / "history.db"
    storage.save_detections(_sample_df(), source="live", db_path=str(db_path))
    storage.save_detections(_sample_df(), source="upload", db_path=str(db_path))

    live_only = storage.query_recent(limit=10, source="live", db_path=str(db_path))

    assert len(live_only) == 2
    assert set(live_only["source"]) == {"live"}


def test_query_sources_returns_distinct_sources_sorted(tmp_path):
    db_path = tmp_path / "history.db"
    storage.save_detections(_sample_df(), source="upload", db_path=str(db_path))
    storage.save_detections(_sample_df(), source="live", db_path=str(db_path))

    assert storage.query_sources(db_path=str(db_path)) == ["live", "upload"]


def test_query_trend_buckets_and_counts_attacks(tmp_path):
    db_path = tmp_path / "history.db"
    storage.save_detections(_sample_df(), source="live", db_path=str(db_path))

    trend = storage.query_trend(db_path=str(db_path))

    assert len(trend) == 1  # both rows saved in the same call -> same minute bucket
    row = trend.iloc[0]
    assert row["total"] == 2
    assert row["rf_attacks"] == 1
    assert row["dt_attacks"] == 0


def test_query_all_returns_every_row(tmp_path):
    db_path = tmp_path / "history.db"
    storage.save_detections(_sample_df(), source="live", db_path=str(db_path))
    storage.save_detections(_sample_df(), source="upload", db_path=str(db_path))

    all_rows = storage.query_all(db_path=str(db_path))

    assert len(all_rows) == 4
    assert set(all_rows["source"]) == {"live", "upload"}


def test_query_distinct_ips_sorted(tmp_path):
    db_path = tmp_path / "history.db"
    storage.save_detections(_sample_df(), source="live", db_path=str(db_path))

    assert storage.query_distinct_ips(db_path=str(db_path)) == ["10.0.0.1", "10.0.0.2"]


def test_query_by_ip_returns_only_that_ip(tmp_path):
    db_path = tmp_path / "history.db"
    storage.save_detections(_sample_df(), source="live", db_path=str(db_path))

    rows = storage.query_by_ip("10.0.0.1", db_path=str(db_path))

    assert len(rows) == 1
    assert set(rows["src_ip"]) == {"10.0.0.1"}


def test_query_ip_summary_counts_and_timestamps(tmp_path):
    db_path = tmp_path / "history.db"
    storage.save_detections(_sample_df(), source="live", db_path=str(db_path))

    ip_summary = storage.query_ip_summary("10.0.0.1", db_path=str(db_path))

    assert ip_summary["total"] == 1
    assert ip_summary["rf_attacks"] == 1  # 10.0.0.1's RF verdict is ATTACK
    assert ip_summary["dt_attacks"] == 0
    assert ip_summary["first_seen"] is not None
    assert ip_summary["last_seen"] is not None
