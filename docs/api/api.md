# REST API

A read-only JSON API over the persisted detection history
(`data/history.db`). Standard-library only — no framework.

## Running

```bash
python -m nids.api          # 127.0.0.1:8600
# or
make api
```

Configure via env: `NIDS_API_HOST`, `NIDS_API_PORT`, and optional
`NIDS_API_TOKEN`.

## Authentication

Optional. When `NIDS_API_TOKEN` is set, every request must send:

```
Authorization: Bearer <token>
```

Requests without a valid token get `401 {"error": "unauthorized"}`. When the
token is unset, the API is open (bind to localhost only in that case).

## Endpoints

### `GET /health`

Liveness check.

- **Response** `200`
  ```json
  { "status": "ok", "service": "nids-api", "version": "8.0.0" }
  ```

### `GET /api/summary`

Totals across all history.

- **Response** `200`
  ```json
  { "total": 1240, "rf_attacks": 322, "dt_attacks": 298 }
  ```

### `GET /api/detections`

Most recent detections.

- **Query params**
  | Name | Required | Default | Description |
  | --- | --- | --- | --- |
  | `limit` | No | 100 | Max rows to return (1–10000). |
  | `source` | No | — | Filter by source (`live` / `upload`). |
- **Response** `200`
  ```json
  { "count": 100, "detections": [ { "id": 1, "captured_at": "...", "src_ip": "...", "rf_verdict": "...", "dt_verdict": "..." } ] }
  ```

### `GET /api/ip/<ip>`

All persisted detections for one source IP, plus a summary.

- **Response** `200`
  ```json
  { "ip": "8.8.8.8", "total": 3, "rf_attacks": 2, "dt_attacks": 1,
    "first_seen": "...", "last_seen": "...", "detections": [ ... ] }
  ```

### Errors

| Status | Body | When |
| --- | --- | --- |
| 400 | `{"error": "limit must be an integer", ...}` | Malformed/out-of-range `limit`, or empty IP. |
| 401 | `{"error": "unauthorized"}` | Missing/invalid bearer token. |
| 404 | `{"error": "not found", "path": "..."}` | Unknown route. |

## Notes

- The API only reads; it never writes to or mutates the database.
- It shares the same SQLite file as the dashboard, so data appears as soon
  as the dashboard persists it.
