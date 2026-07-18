# Architecture

## Overview

The system has two independent data paths that both feed the same
classification + display pipeline:

1. **Training path** (offline): `data/nsl-kdd/KDDTrain+.txt` →
   `scripts/train_models.py` → `models/rf_model.pkl`, `models/dt_model.pkl`,
   `models/iforest_model.pkl`.
2. **Inference path** (runtime, in `src/nids/app.py`):
   - Live packets (scapy `sniff`) or an uploaded `.pcap` (scapy `rdpcap`)
   - → `src/nids/features.py::packets_to_df` (maps raw packets to the
     41 NSL-KDD feature columns, computing `count`/`srv_count`/`*_rate`
     over a real trailing 2-second/100-connection window)
   - → `preprocess_data` (label-encodes `protocol_type`, `service`, `flag`
     using encoders fit on the training set)
   - → `rf_model.predict` / `dt_model.predict` / `iforest_model.predict` (if present)
   - → `src/nids/triage.py::add_triage_columns` (model-vote risk score and severity)
   - → `src/nids/storage.py::save_detections` (persists the classified batch to `data/history.db`)
   - → if any model's attack rate crosses the CRITICAL threshold,
     `src/nids/alerts.py::send_critical_alert` fans out to configured channels
   - → Streamlit tables + Altair charts + rule-based summary + History tab.

## Why feature engineering is a separate module

`src/nids/features.py` has no Streamlit dependency, so it can be:
- Unit tested directly (`tests/test_features.py`), and
- Reused by `scripts/train_models.py` so training and inference always
  agree on the feature schema.

The same reasoning applies to the other logic modules — `storage.py`,
`alerts.py`, `anomaly.py`, `triage.py` (cross-model risk), `geo.py` (IP classification + optional GeoIP),
`reporting.py` (PDF generation), `throughput.py` (per-second aggregation),
`notify.py` (beep/notification HTML), and `netcheck.py` (capture readiness).
Each is pure/stdlib-only (plus pandas/optional libs where needed) so it can be unit
tested and mocked without a Streamlit runtime.

## Live-capture windowing

Before capture begins, `netcheck.capture_interfaces()` normalizes the adapters
reported by Scapy into stable identifiers and friendly labels. `app.py` passes
the chosen identifier to `sniff(iface=...)` and prevents adapter changes while
the session is running. On Windows, the identifier is the Npcap network name;
Linux/macOS normally use the native interface name.

Adapter selection does not imply whole-LAN visibility. A normal endpoint sensor
sees traffic delivered to its selected adapter. SPAN/port mirroring, a network
TAP, or gateway/bridge placement is required to observe other hosts' switched
unicast traffic.

`packets_to_df` computes `count`/`srv_count`/`serror_rate`/`same_srv_rate`
(and their `dst_host_*` counterparts) from a trailing window of packets to
the same destination IP — capped at 2 seconds and the last 100 connections,
using each packet's own scapy capture timestamp (`pkt.time`). For this to
work on live traffic, `app.py`'s live-capture loop keeps a rolling buffer of
raw scapy packets in `st.session_state.raw_packets` (not just the derived
rows) and recomputes the window on every tick.

## Detection persistence

Every classified batch is written to `data/history.db` (SQLite,
gitignored — it's runtime-generated). To avoid re-inserting the same
rolling display window on every live-capture refresh,
`display_results` never persists — only the two call sites that produce a
genuinely new batch do:
- the live-capture loop persists just that tick's newest rows, and
- the pcap-upload handler persists once per uploaded file.

## Alerting

`alerts.py` supports five independent channels (Slack incoming webhook,
generic JSON webhook, SMTP email, PagerDuty, and Microsoft Teams), each optional via `.env`. A
failure in one channel doesn't block the others, and alerting can never
crash the dashboard (exceptions are swallowed and logged as "not sent").
Alerts are cooldown-throttled per model (`ALERT_COOLDOWN_SECONDS`) since
Streamlit reruns constantly during live capture.

## Third model: Isolation Forest

Unlike RF/DT (supervised, trained on labeled attack/normal traffic),
`IsolationForest` is trained unsupervised on **normal-only** traffic, so it
learns what "normal" looks like and flags statistical outliers — useful for
catching attack patterns not present in the NSL-KDD training labels.
`anomaly.py` translates its `{1, -1}` predictions into the same clean
`Attack`/`Normal` verdict convention the UI uses for RF/DT. If
`models/iforest_model.pkl` doesn't exist (e.g. before re-running
`scripts/train_models.py`), the app falls back to the original two-model view.

## Consensus triage

`triage.py` does not retrain, average, or override the models. Each available
`Attack` verdict contributes one vote. The ratio of attack votes to available
models becomes a 0–100 score and maps to Clear (0), Guarded (1–49), Elevated
(50–74), or Critical (75–100). With two models, scores are 0/50/100; with all
three, they are 0/33/67/100. The raw verdict columns remain the source evidence.

`storage.py` persists `anomaly_verdict`, `risk_score`, and `triage`. Opening a
legacy database adds missing columns and normalizes decorated verdict strings
to `Attack`/`Normal` in place without deleting old history.

## Interface shell

`app.py` keeps one compact sidebar for identity, access, model accuracy, and the
critical threshold. Notification preferences are fixed beside the Streamlit
deployment toolbar. The primary navigation opens on Dashboard, followed by Live
Capture, Upload PCAP, Model Logic, Autonomy, History, and Credits. Dashboard owns
aggregate session analytics; Live Capture owns printing, screen recording, packet
controls, the stable 60-second throughput monitor, and detailed model-result graphs.
About is a secondary dialog opened from Credits and contains the technology list.
Role-first sign-in selects Administrator or Viewer before rendering
the credential form, while authorization is still determined by the
authenticated account rather than client-side selection.

## Policy-governed autonomy

`autonomy.py` is a control plane downstream of immutable model verdicts and
consensus triage. It correlates high-risk rows into stable per-source incidents,
persists actions and audit events, and exposes Shadow, Approval, and Autonomous
modes. UI mode selection cannot bypass `NIDS_AUTONOMY_EXECUTE`; private-source
protection, maximum active blocks, TTL rollback, validated argv commands, and
no-shell execution remain server-side guardrails. Behavior drift recommends a
reviewed offline retraining run but never replaces models automatically.

## Container topology

The v11 image contains one immutable application runtime. Its default command
serves Streamlit as UID/GID 10001, while Compose can override the command for the
read-only REST API. Both processes use `/data/history.db`; local Compose mounts
the version-neutral `nids-history` volume there and Render attaches its persistent disk there.
Optional Viewer registrations use `/data/auth.db` on the same persistent volume.
`NIDS_HISTORY_VOLUME` can point Compose at an older volume during migration.

The default dashboard and optional API drop every Linux capability, enable
`no-new-privileges`, use a read-only root filesystem, and receive writable `/tmp`
space through tmpfs. Raw capture is a separate Linux-only Compose profile with
host networking and only `NET_RAW`/`NET_ADMIN`. Windows Npcap remains a native
host dependency and is not part of the Linux image.

Streamlit startup and the image health check read the runtime `PORT`, falling
back to 8501 locally. The API keeps its own `/health` check on port 8600.

## Known simplification (tracked in ROADMAP.md)

The windowed features above are still an approximation of the true NSL-KDD
connection-record definitions (which are computed per-*connection*, not
per-*packet*, and use additional signals this system doesn't parse). Live
traffic accuracy will still generally trail the reported test-set accuracy
shown in the sidebar (which is measured on the real NSL-KDD test set).

## Model I/O contract

- Input: DataFrame with exactly `MODEL_FEATURES` (see `config/features.yaml`), in order.
- RF/DT output: `0` (normal) or `1` (attack) per row.
- Isolation Forest output: `1` (inlier/normal) or `-1` (outlier/anomaly) per row,
  translated via `anomaly.to_verdict`/`anomaly.to_binary`.
