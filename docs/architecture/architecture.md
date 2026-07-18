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
   - → `src/nids/storage.py::save_detections` (persists the classified batch to `data/history.db`)
   - → if any model's attack rate crosses the CRITICAL threshold,
     `src/nids/alerts.py::send_critical_alert` fans out to configured channels
   - → Streamlit tables + Altair charts + rule-based summary + "📜 History" tab.

## Why feature engineering is a separate module

`src/nids/features.py` has no Streamlit dependency, so it can be:
- Unit tested directly (`tests/test_features.py`), and
- Reused by `scripts/train_models.py` so training and inference always
  agree on the feature schema.

The same reasoning applies to `storage.py`, `alerts.py`, and `anomaly.py` —
each is pure/stdlib-only (plus pandas where needed) so it can be unit
tested and mocked without a Streamlit runtime.

## Live-capture windowing

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
rolling display window on every ~0.1s live-capture tick,
`display_results` never persists — only the two call sites that produce a
genuinely new batch do:
- the live-capture loop persists just that tick's newest rows, and
- the pcap-upload handler persists once per uploaded file.

## Alerting

`alerts.py` supports three independent channels (Slack incoming webhook,
generic JSON webhook, SMTP email), each entirely optional via `.env`. A
failure in one channel doesn't block the others, and alerting can never
crash the dashboard (exceptions are swallowed and logged as "not sent").
Alerts are cooldown-throttled per model (`ALERT_COOLDOWN_SECONDS`) since
Streamlit reruns constantly during live capture.

## Third model: Isolation Forest

Unlike RF/DT (supervised, trained on labeled attack/normal traffic),
`IsolationForest` is trained unsupervised on **normal-only** traffic, so it
learns what "normal" looks like and flags statistical outliers — useful for
catching attack patterns not present in the NSL-KDD training labels.
`anomaly.py` translates its `{1, -1}` predictions into the same
ATTACK/Normal verdict convention the UI uses for RF/DT. If
`models/iforest_model.pkl` doesn't exist (e.g. before re-running
`scripts/train_models.py`), the app falls back to the original two-model view.

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
