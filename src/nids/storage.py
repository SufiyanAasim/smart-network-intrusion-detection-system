"""SQLite-backed persistence for IDS detections.

The Streamlit UI only keeps the last 100 rows in memory for display. This
module persists every classified packet/connection to data/history.db so
history survives a rerun/restart and can be queried later.
"""

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

import pandas as pd

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "history.db",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_at TEXT NOT NULL,
    source TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    protocol_type TEXT,
    service TEXT,
    flag TEXT,
    src_bytes INTEGER,
    count INTEGER,
    serror_rate REAL,
    rf_verdict TEXT,
    dt_verdict TEXT
);
"""


@contextmanager
def get_connection(db_path=DEFAULT_DB_PATH):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def save_detections(df_display, source, db_path=DEFAULT_DB_PATH):
    """Persist a batch of already-classified rows (with RF/DT Analysis columns)."""
    if df_display is None or df_display.empty:
        return

    now = datetime.now(timezone.utc).isoformat()
    rows = [
        (
            now,
            source,
            row.get("src_ip"),
            row.get("dst_ip"),
            row.get("protocol_type"),
            row.get("service"),
            row.get("flag"),
            int(row.get("src_bytes", 0) or 0),
            int(row.get("count", 0) or 0),
            float(row.get("serror_rate", 0.0) or 0.0),
            row.get("RF Analysis"),
            row.get("DT Analysis"),
        )
        for _, row in df_display.iterrows()
    ]

    with get_connection(db_path) as conn:
        conn.executemany(
            """
            INSERT INTO detections
                (captured_at, source, src_ip, dst_ip, protocol_type, service, flag,
                 src_bytes, count, serror_rate, rf_verdict, dt_verdict)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )


def query_recent(limit=100, source=None, db_path=DEFAULT_DB_PATH):
    """Return the most recent `limit` persisted detections, newest first.

    `source`, if given (e.g. "live" or "upload"), restricts to that source.
    """
    query = "SELECT * FROM detections"
    params = []
    if source:
        query += " WHERE source = ?"
        params.append(source)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with get_connection(db_path) as conn:
        return pd.read_sql_query(query, conn, params=tuple(params))


def query_sources(db_path=DEFAULT_DB_PATH):
    """Return the distinct `source` values seen so far (e.g. ["live", "upload"])."""
    with get_connection(db_path) as conn:
        return pd.read_sql_query(
            "SELECT DISTINCT source FROM detections ORDER BY source", conn
        )["source"].tolist()


def query_trend(bucket_format="%Y-%m-%d %H:%M", db_path=DEFAULT_DB_PATH):
    """Return RF/DT attack vs. total counts bucketed by time, oldest first.

    `bucket_format` is an SQLite strftime() format applied to `captured_at`
    (ISO 8601 UTC) — the default buckets by minute. Powers the History tab's
    trend chart.
    """
    with get_connection(db_path) as conn:
        return pd.read_sql_query(
            """
            SELECT
                strftime(?, captured_at) AS bucket,
                SUM(CASE WHEN rf_verdict LIKE '%ATTACK%' THEN 1 ELSE 0 END) AS rf_attacks,
                SUM(CASE WHEN dt_verdict LIKE '%ATTACK%' THEN 1 ELSE 0 END) AS dt_attacks,
                COUNT(*) AS total
            FROM detections
            GROUP BY bucket
            ORDER BY bucket
            """,
            conn,
            params=(bucket_format,),
        )


def query_summary(db_path=DEFAULT_DB_PATH):
    """Return total rows and attack counts per model across all history."""
    with get_connection(db_path) as conn:
        return pd.read_sql_query(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN rf_verdict LIKE '%ATTACK%' THEN 1 ELSE 0 END) AS rf_attacks,
                SUM(CASE WHEN dt_verdict LIKE '%ATTACK%' THEN 1 ELSE 0 END) AS dt_attacks
            FROM detections
            """,
            conn,
        ).iloc[0]
