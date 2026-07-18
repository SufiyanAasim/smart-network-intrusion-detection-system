# Docker and Docker Compose deployment

S-NIDS v11.0.0 uses one hardened image for the Streamlit dashboard and the
read-only REST API. The default Compose service runs without Linux capabilities;
raw host capture is isolated behind an explicit Linux-only profile.

## Prerequisites

- Docker Engine 24+ with Compose v2
- At least 2 GB of memory for the scientific Python runtime and models
- A generated PBKDF2 password hash before exposing the dashboard publicly

Create the local environment file:

```bash
cp .env.example .env
python src/nids/auth.py
```

Paste the generated value into `NIDS_AUTH_PASSWORD_HASH` in `.env`. Do not put
plaintext passwords or committed secrets in Compose or the image.

Autonomous response remains safe by default in containers:

```env
NIDS_AUTONOMY_MODE=shadow
NIDS_AUTONOMY_EXECUTE=false
```

Only the Linux `capture` profile has the network capabilities that could apply
a response. Validate Shadow and Approval evidence before enabling execution;
keep private-source containment disabled unless the deployment is explicitly
designed and tested for LAN enforcement.

## Dashboard

```bash
docker compose config
docker compose up --build
```

Open `http://localhost:8501`. Change only the host-side port with
`NIDS_DASHBOARD_PORT`; the container continues to listen on 8501.

Detection history is stored in the version-neutral `nids-history` named volume at
`/data/history.db`. Optional Viewer registrations use `/data/auth.db` in that
same volume. The root filesystem is read-only and `/tmp` is an isolated
memory-backed filesystem. Keep `NIDS_SIGNUP_ENABLED=false` on public deployments;
enable it only for a trusted instance where Viewer self-registration is intended.
During an upgrade from a versioned volume, set `NIDS_HISTORY_VOLUME` to that
existing volume name, verify the history, then migrate it to `nids-history`.

## Dashboard and REST API

```bash
docker compose --profile api up --build
```

The API is exposed at `http://localhost:8600` and shares the history volume with
the dashboard. Set `NIDS_API_TOKEN` before exposing it outside localhost. Change
the host-side port with `NIDS_API_EXPOSE_PORT`.

Health endpoints:

- Dashboard: `GET /_stcore/health`
- API: `GET /health`

## Linux live-capture profile

```bash
docker compose --profile capture up --build nids-capture
```

This profile uses host networking and only adds `NET_RAW` and `NET_ADMIN`. Its
dashboard is therefore available on the host at port 8501. Treat this as an
elevated local deployment and do not expose it directly to an untrusted network.

Npcap cannot be installed or used inside this Linux image. On Windows, use Npcap
with the native source/desktop app, or use Docker's default PCAP-upload workflow.

## Render Blueprint

`render.yaml` provisions the dashboard from the same Dockerfile with:

- the `main` branch and deploys only after checks pass;
- a persistent `/data` disk for SQLite history;
- the Streamlit health endpoint;
- `$PORT` support in both startup and health checks; and
- mandatory `NIDS_AUTH_PASSWORD_HASH` secret entry; and
- an explicit `NIDS_SIGNUP_ENABLED=false` production default.

The Blueprint deliberately selects Render Starter. A persistent disk cannot be
attached to a Free web service; changing the plan to Free would make detection
history ephemeral and invalidates the declared disk.

## Operations

```bash
docker compose logs --follow nids
docker compose ps
docker compose down
```

`docker compose down` preserves the named history volume. Adding `--volumes`
deletes that database volume and should only be used when loss of history is
intentional and a verified backup exists.

Rebuild with current base-image patches before releases:

```bash
docker compose build --pull
docker compose up --detach
```

The container CI workflow validates Compose, builds the image from scratch, and
smoke-tests both dashboard and API health endpoints on every relevant change.

## Troubleshooting

- **Dashboard is unhealthy:** inspect `docker compose logs nids` and confirm the
  selected host port is free.
- **API returns 401:** pass `Authorization: Bearer <NIDS_API_TOKEN>`.
- **History disappears:** confirm `/data` is backed by `nids-history` locally
  or the persistent disk on Render.
- **Capture permission error:** use the capture profile on a Linux Docker host;
  Docker Desktop on Windows is not equivalent to native Npcap capture.
