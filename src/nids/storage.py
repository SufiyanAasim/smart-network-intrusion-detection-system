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

# Where history is persisted. NIDS_DB_PATH overrides the in-repo default —
# required for the packaged desktop build, whose code lives in a read-only
# temp dir that is wiped on exit, and useful for pointing at a volume.
DEFAULT_DB_PATH = os.environ.get("NIDS_DB_PATH") or os.path.join(
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
    dt_verdict TEXT,
    anomaly_verdict TEXT,
    triage TEXT,
    risk_score INTEGER
);
"""

SCHEMA_MIGRATIONS = {
    "anomaly_verdict": "TEXT",
    "triage": "TEXT",
    "risk_score": "INTEGER",
}


def _migrate_schema(conn):
    """Bring databases from earlier releases up to the current schema."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(detections)")}
    for column, sql_type in SCHEMA_MIGRATIONS.items():
        if column not in existing:
            try:
                conn.execute(f"ALTER TABLE detections ADD COLUMN {column} {sql_type}")
            except sqlite3.OperationalError as exc:
                # Two dashboard/API connections may race on the first
                # open. Ignore only the benign duplicate-column result.
                if "duplicate column name" not in str(exc).lower():
                    raise

    # Earlier builds stored emoji-decorated verdicts. Normalize them in place
    # so history tables, exports, charts, and the API all use the same concise
    # operator-facing vocabulary as current detections.
    for column in ("rf_verdict", "dt_verdict", "anomaly_verdict"):
        conn.execute(
            f"UPDATE detections SET {column} = 'Attack' "
            f"WHERE {column} IS NOT NULL AND lower({column}) LIKE '%attack%' "
            f"AND {column} != 'Attack'"
        )
        conn.execute(
            f"UPDATE detections SET {column} = 'Normal' "
            f"WHERE {column} IS NOT NULL AND lower({column}) LIKE '%normal%' "
            f"AND {column} != 'Normal'"
        )


def _number(value, cast, default=0):
    """Coerce dataframe scalars while treating None/NaN as a safe default."""
    if value is None or pd.isna(value):
        return default
    return cast(value)


@contextmanager
def get_connection(db_path=DEFAULT_DB_PATH):
    parent = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10)
    try:
        conn.execute("PRAGMA busy_timeout = 10000")
        conn.execute(SCHEMA)
        _migrate_schema(conn)
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
            _number(row.get("src_bytes"), int),
            _number(row.get("count"), int),
            _number(row.get("serror_rate"), float, 0.0),
            row.get("RF Analysis"),
            row.get("DT Analysis"),
            row.get("Anomaly Analysis"),
            row.get("Triage"),
            _number(row.get("Risk Score"), int),
        )
        for _, row in df_display.iterrows()
    ]

    with get_connection(db_path) as conn:
        conn.executemany(
            """
            INSERT INTO detections
                (captured_at, source, src_ip, dst_ip, protocol_type, service, flag,
                 src_bytes, count, serror_rate, rf_verdict, dt_verdict,
                 anomaly_verdict, triage, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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


def query_all(db_path=DEFAULT_DB_PATH):
    """Return every persisted detection, newest first.

    Used for full-history export — unlike `query_recent`, there is no row
    limit, so callers should be prepared for large results.
    """
    with get_connection(db_path) as conn:
        return pd.read_sql_query(
            "SELECT * FROM detections ORDER BY id DESC", conn
        )


def query_distinct_ips(db_path=DEFAULT_DB_PATH):
    """Return every distinct source IP seen so far, sorted."""
    with get_connection(db_path) as conn:
        return pd.read_sql_query(
            "SELECT DISTINCT src_ip FROM detections "
            "WHERE src_ip IS NOT NULL ORDER BY src_ip",
            conn,
        )["src_ip"].tolist()


def query_by_ip(src_ip, limit=500, db_path=DEFAULT_DB_PATH):
    """Return all persisted detections for one source IP, newest first."""
    with get_connection(db_path) as conn:
        return pd.read_sql_query(
            "SELECT * FROM detections WHERE src_ip = ? ORDER BY id DESC LIMIT ?",
            conn,
            params=(src_ip, limit),
        )


def query_triage(min_risk=50, limit=100, source=None, db_path=DEFAULT_DB_PATH):
    """Return the newest rows at or above a consensus risk threshold."""
    query = "SELECT * FROM detections WHERE COALESCE(risk_score, 0) >= ?"
    params = [int(min_risk)]
    if source:
        query += " AND source = ?"
        params.append(source)
    query += " ORDER BY risk_score DESC, id DESC LIMIT ?"
    params.append(int(limit))
    with get_connection(db_path) as conn:
        return pd.read_sql_query(query, conn, params=tuple(params))


def query_ip_summary(src_ip, db_path=DEFAULT_DB_PATH):
    """Return per-IP stats: total rows, RF/DT attack counts, first/last seen."""
    with get_connection(db_path) as conn:
        return pd.read_sql_query(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN rf_verdict LIKE '%ATTACK%' THEN 1 ELSE 0 END) AS rf_attacks,
                SUM(CASE WHEN dt_verdict LIKE '%ATTACK%' THEN 1 ELSE 0 END) AS dt_attacks,
                SUM(CASE WHEN anomaly_verdict LIKE '%ATTACK%' THEN 1 ELSE 0 END) AS anomaly_attacks,
                SUM(CASE WHEN triage = 'Critical' THEN 1 ELSE 0 END) AS critical_triage,
                AVG(COALESCE(risk_score, 0)) AS avg_risk_score,
                MIN(captured_at) AS first_seen,
                MAX(captured_at) AS last_seen
            FROM detections
            WHERE src_ip = ?
            """,
            conn,
            params=(src_ip,),
        ).iloc[0]


def query_summary(db_path=DEFAULT_DB_PATH):
    """Return total rows and attack counts per model across all history."""
    with get_connection(db_path) as conn:
        return pd.read_sql_query(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN rf_verdict LIKE '%ATTACK%' THEN 1 ELSE 0 END) AS rf_attacks,
                SUM(CASE WHEN dt_verdict LIKE '%ATTACK%' THEN 1 ELSE 0 END) AS dt_attacks,
                SUM(CASE WHEN anomaly_verdict LIKE '%ATTACK%' THEN 1 ELSE 0 END) AS anomaly_attacks,
                SUM(CASE WHEN triage = 'Critical' THEN 1 ELSE 0 END) AS critical_triage,
                AVG(COALESCE(risk_score, 0)) AS avg_risk_score
            FROM detections
            """,
            conn,
        ).iloc[0]
