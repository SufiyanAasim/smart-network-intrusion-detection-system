"""Policy-governed autonomous response for Cipher v11.

The control plane is deliberately separate from model inference.  Models emit
evidence; this module correlates that evidence, applies explicit guardrails,
persists every decision, and (only when server-side execution is enabled)
creates reversible host-firewall blocks.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform
import sqlite3
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pandas as pd

from nids import storage
from nids.firewall import is_blockable

MODE_SHADOW = "shadow"
MODE_APPROVAL = "approval"
MODE_AUTONOMOUS = "autonomous"
MODES = (MODE_SHADOW, MODE_APPROVAL, MODE_AUTONOMOUS)

ACTION_BLOCK = "block_source"
ACTION_STATUSES = (
    "simulated", "pending", "guarded", "active", "denied", "rolled_back", "failed"
)

AUTONOMY_SCHEMA = """
CREATE TABLE IF NOT EXISTS autonomy_incidents (
    incident_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    source TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    max_risk INTEGER NOT NULL,
    avg_risk REAL NOT NULL,
    severity TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    evidence_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS autonomy_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    expires_at TEXT,
    actor TEXT NOT NULL,
    command_preview TEXT NOT NULL,
    error TEXT,
    UNIQUE(incident_id, action_type)
);
CREATE TABLE IF NOT EXISTS autonomy_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    incident_id TEXT,
    action_id INTEGER,
    details_json TEXT NOT NULL
);
"""


def _env_int(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _env_bool(name, default=False):
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Policy:
    mode: str = MODE_SHADOW
    min_risk: int = 90
    min_events: int = 3
    correlation_window_seconds: int = 300
    block_ttl_minutes: int = 30
    max_active_blocks: int = 5
    execution_enabled: bool = False
    allow_private_sources: bool = False


def policy_from_env():
    mode = os.environ.get("NIDS_AUTONOMY_MODE", MODE_SHADOW).strip().lower()
    if mode not in MODES:
        mode = MODE_SHADOW
    return Policy(
        mode=mode,
        min_risk=_env_int("NIDS_AUTONOMY_MIN_RISK", 90, 50, 100),
        min_events=_env_int("NIDS_AUTONOMY_MIN_EVENTS", 3, 1, 1000),
        correlation_window_seconds=_env_int(
            "NIDS_AUTONOMY_WINDOW_SECONDS", 300, 30, 86400
        ),
        block_ttl_minutes=_env_int("NIDS_AUTONOMY_BLOCK_TTL_MINUTES", 30, 1, 1440),
        max_active_blocks=_env_int("NIDS_AUTONOMY_MAX_ACTIVE_BLOCKS", 5, 1, 100),
        execution_enabled=_env_bool("NIDS_AUTONOMY_EXECUTE", False),
        allow_private_sources=_env_bool("NIDS_AUTONOMY_ALLOW_PRIVATE", False),
    )


def _now(now=None):
    return now or datetime.now(timezone.utc)


def _ensure_schema(conn):
    conn.executescript(AUTONOMY_SCHEMA)


def ensure_schema(db_path=storage.DEFAULT_DB_PATH):
    with storage.get_connection(db_path) as conn:
        _ensure_schema(conn)


def _audit(conn, event_type, actor, incident_id=None, action_id=None, **details):
    conn.execute(
        """INSERT INTO autonomy_audit
           (occurred_at, event_type, actor, incident_id, action_id, details_json)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            _now().isoformat(), event_type, actor, incident_id, action_id,
            json.dumps(details, sort_keys=True, default=str),
        ),
    )


def _incident_id(src_ip, timestamp, window_seconds):
    bucket = int(timestamp.timestamp()) // window_seconds
    return hashlib.sha256(f"{src_ip}|{bucket}".encode()).hexdigest()[:20]


def _protected_source(ip, policy):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return address.is_private and not policy.allow_private_sources


def correlate_batch(df, source, mode=None, policy=None, now=None):
    """Correlate model evidence into per-source response decisions."""
    policy = policy or policy_from_env()
    mode = mode if mode in MODES else policy.mode
    timestamp = _now(now)
    if df is None or df.empty or "src_ip" not in df or "Risk Score" not in df:
        return []

    decisions = []
    for src_ip, group in df.dropna(subset=["src_ip"]).groupby("src_ip"):
        risks = pd.to_numeric(group["Risk Score"], errors="coerce").fillna(0)
        event_count = int((risks >= policy.min_risk).sum())
        max_risk = int(risks.max())
        if max_risk < policy.min_risk:
            continue
        targets = sorted({str(value) for value in group.get("dst_ip", []) if pd.notna(value)})
        protocols = sorted({str(value) for value in group.get("protocol_type", []) if pd.notna(value)})
        eligible = event_count >= policy.min_events and is_blockable(str(src_ip))
        protected = _protected_source(str(src_ip), policy)
        if not eligible:
            status = "insufficient_evidence"
        elif protected:
            status = "protected_source"
        elif mode == MODE_SHADOW:
            status = "simulated"
        elif mode == MODE_APPROVAL:
            status = "pending_approval"
        elif policy.execution_enabled:
            status = "pending_execution"
        else:
            status = "execution_guarded"

        decisions.append({
            "incident_id": _incident_id(
                str(src_ip), timestamp, policy.correlation_window_seconds
            ),
            "created_at": timestamp.isoformat(),
            "source": source,
            "src_ip": str(src_ip),
            "event_count": event_count,
            "max_risk": max_risk,
            "avg_risk": round(float(risks.mean()), 2),
            "severity": "Critical" if max_risk >= 90 else "Elevated",
            "mode": mode,
            "status": status,
            "eligible": eligible and not protected,
            "evidence": {"targets": targets, "protocols": protocols, "rows": len(group)},
        })
    return decisions


def _command_pair(ip, action_id, system=None):
    """Return reversible argv commands; never invoke a shell."""
    if not is_blockable(ip):
        raise ValueError("target is not a blockable IP address")
    system = system or platform.system()
    rule_name = f"NIDS-AUTO-{action_id}"
    if system == "Windows":
        apply_cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}",
        ]
        rollback_cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}",
        ]
    else:
        apply_cmd = [
            "iptables", "-I", "INPUT", "-s", ip, "-m", "comment",
            "--comment", rule_name, "-j", "DROP",
        ]
        rollback_cmd = [
            "iptables", "-D", "INPUT", "-s", ip, "-m", "comment",
            "--comment", rule_name, "-j", "DROP",
        ]
    return apply_cmd, rollback_cmd


def record_batch(df, source, mode=None, actor="system", policy=None,
                 db_path=storage.DEFAULT_DB_PATH, now=None, runner=subprocess.run):
    """Persist correlated incidents/actions and execute only when explicitly enabled."""
    policy = policy or policy_from_env()
    decisions = correlate_batch(df, source, mode=mode, policy=policy, now=now)
    timestamp = _now(now)
    action_ids = []
    with storage.get_connection(db_path) as conn:
        _ensure_schema(conn)
        for item in decisions:
            conn.execute(
                """INSERT INTO autonomy_incidents
                   (incident_id, created_at, updated_at, source, src_ip, event_count,
                    max_risk, avg_risk, severity, mode, status, evidence_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(incident_id) DO UPDATE SET
                     updated_at=excluded.updated_at,
                     event_count=MAX(event_count, excluded.event_count),
                     max_risk=MAX(max_risk, excluded.max_risk),
                     avg_risk=excluded.avg_risk,
                     mode=excluded.mode,
                     status=excluded.status,
                     evidence_json=excluded.evidence_json""",
                (
                    item["incident_id"], item["created_at"], timestamp.isoformat(),
                    item["source"], item["src_ip"], item["event_count"],
                    item["max_risk"], item["avg_risk"], item["severity"],
                    item["mode"], item["status"], json.dumps(item["evidence"]),
                ),
            )
            if not item["eligible"]:
                _audit(conn, "incident_guarded", actor, item["incident_id"],
                       reason=item["status"])
                continue
            action_status = {
                MODE_SHADOW: "simulated",
                MODE_APPROVAL: "pending",
                MODE_AUTONOMOUS: "pending" if policy.execution_enabled else "guarded",
            }[item["mode"]]
            preview = f"Temporarily block {item['src_ip']} for {policy.block_ttl_minutes} minutes"
            conn.execute(
                """INSERT INTO autonomy_actions
                   (incident_id, created_at, updated_at, action_type, target, mode,
                    status, expires_at, actor, command_preview, error)
                   VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, NULL)
                   ON CONFLICT(incident_id, action_type) DO UPDATE SET
                     updated_at=excluded.updated_at,
                     mode=excluded.mode,
                     status=CASE WHEN autonomy_actions.status IN ('active','rolled_back','denied')
                                 THEN autonomy_actions.status ELSE excluded.status END,
                     actor=excluded.actor,
                     command_preview=excluded.command_preview""",
                (
                    item["incident_id"], timestamp.isoformat(), timestamp.isoformat(),
                    ACTION_BLOCK, item["src_ip"], item["mode"], action_status,
                    actor, preview,
                ),
            )
            action_id = conn.execute(
                "SELECT id FROM autonomy_actions WHERE incident_id=? AND action_type=?",
                (item["incident_id"], ACTION_BLOCK),
            ).fetchone()[0]
            action_ids.append(action_id)
            _audit(conn, "action_created", actor, item["incident_id"], action_id,
                   mode=item["mode"], status=action_status)

    if policy.execution_enabled and (mode or policy.mode) == MODE_AUTONOMOUS:
        for action_id in action_ids:
            execute_action(
                action_id, actor=actor, policy=policy, db_path=db_path,
                now=timestamp, runner=runner,
            )
    return decisions


def _action_row(action_id, conn):
    row = conn.execute(
        "SELECT * FROM autonomy_actions WHERE id=?", (int(action_id),)
    ).fetchone()
    return row


def execute_action(action_id, actor, policy=None, db_path=storage.DEFAULT_DB_PATH,
                   now=None, runner=subprocess.run):
    """Apply one approved/pending block under server-side guardrails."""
    policy = policy or policy_from_env()
    timestamp = _now(now)
    with storage.get_connection(db_path) as conn:
        _ensure_schema(conn)
        conn.row_factory = sqlite3.Row
        row = _action_row(action_id, conn)
        if row is None:
            return False, "action not found"
        if not policy.execution_enabled:
            return False, "execution is disabled by server policy"
        if row["status"] not in {"pending", "guarded"}:
            return False, f"action is {row['status']}"
        if _protected_source(row["target"], policy):
            return False, "private source is protected by policy"
        active = conn.execute(
            "SELECT COUNT(*) FROM autonomy_actions WHERE status='active'"
        ).fetchone()[0]
        if active >= policy.max_active_blocks:
            return False, "active-block limit reached"
        apply_cmd, _ = _command_pair(row["target"], row["id"])
        try:
            completed = runner(apply_cmd, capture_output=True, text=True, timeout=15, check=False)
            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or "command failed").strip())
        except Exception as exc:
            conn.execute(
                "UPDATE autonomy_actions SET status='failed', updated_at=?, error=? WHERE id=?",
                (timestamp.isoformat(), str(exc)[:500], row["id"]),
            )
            _audit(conn, "action_failed", actor, row["incident_id"], row["id"], error=str(exc))
            return False, str(exc)
        expires_at = timestamp + timedelta(minutes=policy.block_ttl_minutes)
        conn.execute(
            """UPDATE autonomy_actions SET status='active', updated_at=?, expires_at=?,
               actor=?, error=NULL WHERE id=?""",
            (timestamp.isoformat(), expires_at.isoformat(), actor, row["id"]),
        )
        conn.execute(
            "UPDATE autonomy_incidents SET status='contained', updated_at=? WHERE incident_id=?",
            (timestamp.isoformat(), row["incident_id"]),
        )
        _audit(conn, "action_executed", actor, row["incident_id"], row["id"],
               expires_at=expires_at.isoformat())
        return True, "temporary block applied"


def decide_action(action_id, decision, actor, policy=None,
                  db_path=storage.DEFAULT_DB_PATH, runner=subprocess.run):
    if decision not in {"approve", "deny"}:
        raise ValueError("decision must be approve or deny")
    with storage.get_connection(db_path) as conn:
        _ensure_schema(conn)
        conn.row_factory = sqlite3.Row
        row = _action_row(action_id, conn)
        if row is None:
            return False, "action not found"
        if row["status"] != "pending":
            return False, f"action is {row['status']}"
        if decision == "deny":
            conn.execute(
                "UPDATE autonomy_actions SET status='denied', updated_at=?, actor=? WHERE id=?",
                (_now().isoformat(), actor, row["id"]),
            )
            _audit(conn, "action_denied", actor, row["incident_id"], row["id"])
            return True, "action denied"
        policy = policy or policy_from_env()
        if not policy.execution_enabled:
            conn.execute(
                """UPDATE autonomy_actions SET status='guarded', updated_at=?,
                   actor=? WHERE id=?""",
                (_now().isoformat(), actor, row["id"]),
            )
            _audit(
                conn, "action_approved_guarded", actor, row["incident_id"],
                row["id"], reason="server execution disabled",
            )
            return True, "response approved; execution remains guarded by server policy"
    return execute_action(
        action_id, actor=actor, policy=policy, db_path=db_path, runner=runner
    )


def rollback_action(action_id, actor, db_path=storage.DEFAULT_DB_PATH,
                    runner=subprocess.run, now=None):
    timestamp = _now(now)
    with storage.get_connection(db_path) as conn:
        _ensure_schema(conn)
        conn.row_factory = sqlite3.Row
        row = _action_row(action_id, conn)
        if row is None:
            return False, "action not found"
        if row["status"] != "active":
            return False, f"action is {row['status']}"
        _, rollback_cmd = _command_pair(row["target"], row["id"])
        try:
            completed = runner(rollback_cmd, capture_output=True, text=True, timeout=15, check=False)
            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or "command failed").strip())
        except Exception as exc:
            _audit(conn, "rollback_failed", actor, row["incident_id"], row["id"], error=str(exc))
            return False, str(exc)
        conn.execute(
            "UPDATE autonomy_actions SET status='rolled_back', updated_at=?, actor=? WHERE id=?",
            (timestamp.isoformat(), actor, row["id"]),
        )
        conn.execute(
            "UPDATE autonomy_incidents SET status='released', updated_at=? WHERE incident_id=?",
            (timestamp.isoformat(), row["incident_id"]),
        )
        _audit(conn, "action_rolled_back", actor, row["incident_id"], row["id"])
        return True, "block rolled back"


def expire_actions(db_path=storage.DEFAULT_DB_PATH, runner=subprocess.run, now=None):
    timestamp = _now(now)
    with storage.get_connection(db_path) as conn:
        _ensure_schema(conn)
        rows = conn.execute(
            "SELECT id FROM autonomy_actions WHERE status='active' AND expires_at<=?",
            (timestamp.isoformat(),),
        ).fetchall()
    return [rollback_action(row[0], "system-expiry", db_path, runner, timestamp) for row in rows]


def query_incidents(limit=100, db_path=storage.DEFAULT_DB_PATH):
    with storage.get_connection(db_path) as conn:
        _ensure_schema(conn)
        return pd.read_sql_query(
            "SELECT * FROM autonomy_incidents ORDER BY updated_at DESC LIMIT ?",
            conn, params=(int(limit),),
        )


def query_actions(status=None, limit=100, db_path=storage.DEFAULT_DB_PATH):
    query = "SELECT * FROM autonomy_actions"
    params = []
    if status:
        query += " WHERE status=?"
        params.append(status)
    query += " ORDER BY updated_at DESC LIMIT ?"
    params.append(int(limit))
    with storage.get_connection(db_path) as conn:
        _ensure_schema(conn)
        return pd.read_sql_query(query, conn, params=tuple(params))


def query_audit(limit=200, db_path=storage.DEFAULT_DB_PATH):
    with storage.get_connection(db_path) as conn:
        _ensure_schema(conn)
        return pd.read_sql_query(
            "SELECT * FROM autonomy_audit ORDER BY id DESC LIMIT ?", conn,
            params=(int(limit),),
        )


def query_summary(db_path=storage.DEFAULT_DB_PATH):
    ensure_schema(db_path)
    with storage.get_connection(db_path) as conn:
        return {
            "incidents": conn.execute("SELECT COUNT(*) FROM autonomy_incidents").fetchone()[0],
            "pending": conn.execute("SELECT COUNT(*) FROM autonomy_actions WHERE status='pending'").fetchone()[0],
            "active": conn.execute("SELECT COUNT(*) FROM autonomy_actions WHERE status='active'").fetchone()[0],
            "simulated": conn.execute("SELECT COUNT(*) FROM autonomy_actions WHERE status='simulated'").fetchone()[0],
        }


def drift_report(history_df, recent_size=50):
    """Compare recent numeric behavior with older history; never retrains models."""
    if history_df is None or len(history_df) < max(20, recent_size + 10):
        return {"score": 0, "status": "learning", "features": {}, "retrain_recommended": False}
    recent_size = min(recent_size, max(10, len(history_df) // 3))
    recent = history_df.iloc[:recent_size]
    baseline = history_df.iloc[recent_size:]
    feature_scores = {}
    for feature in ("risk_score", "src_bytes", "count", "serror_rate"):
        if feature not in history_df:
            continue
        base = pd.to_numeric(baseline[feature], errors="coerce").dropna()
        current = pd.to_numeric(recent[feature], errors="coerce").dropna()
        if base.empty or current.empty:
            continue
        scale = float(base.std()) or max(abs(float(base.mean())) * 0.1, 1.0)
        feature_scores[feature] = round(min(100.0, abs(float(current.mean() - base.mean())) / scale * 25), 1)
    score = round(sum(feature_scores.values()) / len(feature_scores), 1) if feature_scores else 0
    status = "drift" if score >= 70 else "watch" if score >= 40 else "stable"
    return {
        "score": score, "status": status, "features": feature_scores,
        "retrain_recommended": score >= 70,
    }
