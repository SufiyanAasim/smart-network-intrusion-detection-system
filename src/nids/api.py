"""Read-only JSON REST API over the detection history.

A small, dependency-free HTTP service (standard-library `http.server`) that
exposes the persisted `data/history.db` as JSON — handy for dashboards,
SIEM ingestion, or scripts. Read-only: it never writes or mutates anything.

Run it with:  python src/nids/api.py  (127.0.0.1:8600 by default)

Optional bearer-token auth: set NIDS_API_TOKEN and send
`Authorization: Bearer <token>`.

Routing logic is factored into `route(...)` so it can be unit tested without
opening a socket.
"""

import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

# Make `nids` importable when this file is run directly from the repo root.
_SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from nids import autonomy, storage, __version__  # noqa: E402

TOKEN_ENV = "NIDS_API_TOKEN"

# Upper bound on ?limit= so a single request can't try to serialize the whole
# history into memory.
MAX_LIMIT = 10_000


def _integer_param(query, name, default, minimum, maximum):
    raw = query.get(name, [str(default)])[0]
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None, {"error": f"{name} must be an integer", "got": raw}
    if value < minimum or value > maximum:
        return None, {
            "error": f"{name} must be between {minimum} and {maximum}",
            "got": value,
        }
    return value, None


def _authorized(auth_header):
    """True if the request is authorized. Open when NIDS_API_TOKEN is unset."""
    token = os.environ.get(TOKEN_ENV)
    if not token:
        return True
    if not auth_header:
        return False
    scheme, separator, supplied = auth_header.partition(" ")
    if not separator or scheme.lower() != "bearer":
        return False
    return hmac.compare_digest(supplied, token)


def route(path, query=None, auth_header=None, db_path=storage.DEFAULT_DB_PATH):
    """Resolve a GET request to (status_code, body_dict).

    Pure function — no I/O beyond the SQLite reads in `storage`. `query` is a
    dict of str->list (as from parse_qs).
    """
    query = query or {}

    if not _authorized(auth_header):
        return 401, {"error": "unauthorized"}

    if path in ("/", "/health"):
        return 200, {"status": "ok", "service": "nids-api", "version": __version__}

    if path == "/api/summary":
        summary = storage.query_summary(db_path=db_path)
        return 200, {
            "total": int(summary["total"] or 0),
            "rf_attacks": int(summary["rf_attacks"] or 0),
            "dt_attacks": int(summary["dt_attacks"] or 0),
            "anomaly_attacks": int(summary["anomaly_attacks"] or 0),
            "critical_triage": int(summary["critical_triage"] or 0),
            "avg_risk_score": round(float(summary["avg_risk_score"] or 0), 1),
        }

    if path == "/api/detections":
        # A non-numeric ?limit= used to raise straight out of the handler as a
        # 500; report it as a client error instead.
        limit, error = _integer_param(query, "limit", 100, 1, MAX_LIMIT)
        if error:
            return 400, error
        source = query.get("source", [None])[0]
        df = storage.query_recent(limit=limit, source=source, db_path=db_path)
        return 200, {"count": len(df), "detections": df.to_dict(orient="records")}

    if path == "/api/triage":
        limit, error = _integer_param(query, "limit", 100, 1, MAX_LIMIT)
        if error:
            return 400, error
        min_risk, error = _integer_param(query, "min_risk", 50, 0, 100)
        if error:
            return 400, error
        source = query.get("source", [None])[0]
        df = storage.query_triage(
            min_risk=min_risk, limit=limit, source=source, db_path=db_path
        )
        return 200, {
            "count": len(df),
            "min_risk": min_risk,
            "detections": df.to_dict(orient="records"),
        }

    if path == "/api/autonomy/summary":
        return 200, autonomy.query_summary(db_path=db_path)

    if path == "/api/autonomy/incidents":
        limit, error = _integer_param(query, "limit", 100, 1, MAX_LIMIT)
        if error:
            return 400, error
        df = autonomy.query_incidents(limit=limit, db_path=db_path)
        return 200, {"count": len(df), "incidents": df.to_dict(orient="records")}

    if path == "/api/autonomy/actions":
        limit, error = _integer_param(query, "limit", 100, 1, MAX_LIMIT)
        if error:
            return 400, error
        status = query.get("status", [None])[0]
        if status and status not in autonomy.ACTION_STATUSES:
            return 400, {"error": "invalid action status", "got": status}
        df = autonomy.query_actions(status=status, limit=limit, db_path=db_path)
        return 200, {"count": len(df), "actions": df.to_dict(orient="records")}

    if path.startswith("/api/ip/"):
        # Percent-decode so IPv6 / escaped values resolve to the stored value.
        ip = unquote(path[len("/api/ip/"):])
        if not ip:
            return 400, {"error": "missing ip"}
        summary = storage.query_ip_summary(ip, db_path=db_path)
        df = storage.query_by_ip(ip, db_path=db_path)
        return 200, {
            "ip": ip,
            "total": int(summary["total"] or 0),
            "rf_attacks": int(summary["rf_attacks"] or 0),
            "dt_attacks": int(summary["dt_attacks"] or 0),
            "anomaly_attacks": int(summary["anomaly_attacks"] or 0),
            "critical_triage": int(summary["critical_triage"] or 0),
            "avg_risk_score": round(float(summary["avg_risk_score"] or 0), 1),
            "first_seen": summary["first_seen"],
            "last_seen": summary["last_seen"],
            "detections": df.to_dict(orient="records"),
        }

    return 404, {"error": "not found", "path": path}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        try:
            parsed = urlparse(self.path)
            status, body = route(
                parsed.path,
                parse_qs(parsed.query),
                self.headers.get("Authorization"),
            )
        except Exception:
            status, body = 500, {"error": "internal server error"}
        payload = json.dumps(body, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # silence default stderr logging
        pass


def serve(host="127.0.0.1", port=8600):  # pragma: no cover - network loop
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"NIDS API listening on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":  # pragma: no cover
    serve(
        host=os.environ.get("NIDS_API_HOST", "127.0.0.1"),
        port=int(os.environ.get("NIDS_API_PORT", "8600")),
    )
