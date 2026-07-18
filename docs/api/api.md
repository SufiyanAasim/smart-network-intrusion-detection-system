# REST API

A dependency-free, read-only JSON API over the persisted detection history.
It never changes detections and shares the dashboard's SQLite database.

## Run

```bash
python src/nids/api.py       # 127.0.0.1:8600
# or
make api
```

Configure `NIDS_API_HOST`, `NIDS_API_PORT`, and optionally `NIDS_API_TOKEN`.

## Authentication

When `NIDS_API_TOKEN` is set, every request must send:

```http
Authorization: Bearer <token>
```

Missing or invalid credentials return `401`. When the token is unset the API
is open; keep its default localhost bind in that mode.

## Endpoints

### `GET /health`

```json
{"status":"ok","service":"nids-api","version":"11.0.0"}
```

### `GET /api/summary`

Returns persisted detection totals and consensus metrics.

```json
{
  "total": 1240,
  "rf_attacks": 322,
  "dt_attacks": 298,
  "anomaly_attacks": 341,
  "critical_triage": 184,
  "avg_risk_score": 31.7
}
```

### `GET /api/detections`

Newest detections, ordered by insertion ID descending.
Model verdict fields use the stable text values `Normal` and `Attack`. Opening
an older database normalizes legacy decorated values before API rows are read.

| Query | Default | Constraint | Meaning |
| --- | ---: | ---: | --- |
| `limit` | 100 | 1–10000 | Maximum returned rows. |
| `source` | — | `live` / `upload` | Optional exact source filter. |

### `GET /api/triage`

Highest-risk detections first, then newest insertion ID. This is the preferred
endpoint for an operator queue or SIEM poller.

| Query | Default | Constraint | Meaning |
| --- | ---: | ---: | --- |
| `min_risk` | 50 | 0–100 | Minimum persisted consensus score. |
| `limit` | 100 | 1–10000 | Maximum returned rows. |
| `source` | — | `live` / `upload` | Optional exact source filter. |

Example:

```bash
curl "http://127.0.0.1:8600/api/triage?min_risk=67&limit=25"
```

```json
{"count":1,"min_risk":67,"detections":[{"risk_score":100,"triage":"Critical"}]}
```

### `GET /api/ip/<ip>`

Returns up to 500 detections for one percent-decoded source IP plus totals,
model attack counts, critical consensus count, average risk, and first/last
seen timestamps.

### `GET /api/autonomy/summary`

Returns correlated incident, pending approval, active block, and Shadow
simulation totals.

### `GET /api/autonomy/incidents`

Returns the newest correlated incidents. `limit` defaults to 100 and is bounded
to 1–10000.

### `GET /api/autonomy/actions`

Returns audited response actions. `limit` is bounded to 1–10000; optional
`status` accepts `simulated`, `pending`, `guarded`, `active`, `denied`,
`rolled_back`, or `failed`. The API remains read-only: approvals and rollbacks
are never exposed as HTTP GET operations.

## Errors and response handling

| Status | Meaning |
| --- | --- |
| 400 | An integer filter is malformed/out of range, or the IP is empty. |
| 401 | Bearer token is missing or invalid. |
| 404 | Route does not exist. |
| 500 | A storage or serialization failure occurred; internals are not exposed. |

Responses are JSON with `Cache-Control: no-store` and
`X-Content-Type-Options: nosniff` headers.
