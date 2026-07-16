# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [4.0.0] - 2026-07-16

### Added
- Configurable CRITICAL threshold — a sidebar slider (`⚙️ Thresholds`,
  default 20%, env default via `CRITICAL_THRESHOLD_PCT`) replaces the
  hardcoded 20% cutoff in `generate_smart_summary`. SUSPICIOUS is still
  anything above 0% and below this.
- History tab trend chart — "Attacks over time" line chart (RF vs. DT,
  per-minute buckets) via new `storage.query_trend()`.

### Notes
- Codename: **Citadel** (Guardian/Security theme), 2-feature release per
  the locked v4–v8 cadence (see RELEASE.md).

## [3.0.0] - 2026-07-16

### Added
- Real windowed `count`/`srv_count`/`*serror_rate`/`*same_srv_rate` feature
  computation in `src/nids/features.py` (trailing 2s / 100-connection
  window, keyed off each packet's capture timestamp), replacing the
  hardcoded single-packet approximation.
- `src/nids/storage.py` — SQLite-backed persistence (`data/history.db`) for
  every classified detection, beyond the in-memory 100-row UI buffer. New
  "📜 History" tab shows totals and the most recent 200 detections.
- `src/nids/alerts.py` — critical-threat alerting via Slack incoming
  webhook, generic webhook, or SMTP email, configured via `.env`. Alerts
  are cooldown-throttled per model (`ALERT_COOLDOWN_SECONDS`, default 60s)
  so a sustained attack doesn't spam every rerun.
- `src/nids/anomaly.py` + Isolation Forest as a third, unsupervised
  comparison model alongside Random Forest and Decision Tree
  (`scripts/train_models.py` now also trains and saves
  `models/iforest_model.pkl`; the app degrades gracefully to the two
  original models if that file isn't present).
- Tests for all of the above (`tests/test_storage.py`, `tests/test_alerts.py`,
  `tests/test_anomaly.py`, plus new windowing tests in `tests/test_features.py`).
- `assets/images/logo.svg` — a Guardian/Security-themed shield logo, shown
  in the app header, sidebar, and README.
- Sidebar "ℹ️ About this project" panel and a live "NIDS v{version}" badge.
- `st.toast` pop-up on critical-threat detection (in addition to the
  existing in-page banner), cooldown-throttled together with alerting.
- Packets-captured session counter in the Live Capture tab.
- Source filter (`All` / `live` / `upload`) on the History tab
  (`storage.query_recent(source=...)`, `storage.query_sources()`).
- Custom dark theme (`.streamlit/config.toml`) matching the logo palette.
- `docs/DATASET.md` — NSL-KDD source, citation, file layout, and column
  meanings.
- `.claude/launch.json` — one-command dev-server launch config for local previewing.

### Changed
- Live-capture loop now keeps a rolling raw-packet buffer
  (`st.session_state.raw_packets`) instead of only accumulating
  already-computed rows, so windowed stats have real history to compute from.
- `display_results` refactored to a single `render_model_column` helper
  shared by all model columns (2 or 3), removing the duplicated
  RF/DT rendering blocks.

### Notes
- Codename: **Watchtower** (Guardian/Security theme).
- Starting with v4.0.0, releases follow a fixed cadence: 2 new features per
  release, except v6.0.0 (Aegis) and v8.0.0 (Cipher) which are grand
  releases bundling 5 new features each. See RELEASE.md.

## [2.0.0] - 2026-07-15

### Added
- Nothing new functionally — this tag marks the current working IDS dashboard
  (live capture, pcap upload, dual-model comparison, explainable AI) as the
  first stable release, on top of the v1.0.0 pre-release restructuring.

### Notes
- v1.0.0 was the pre-release (repo restructuring, docs, CI, tests).
- v2.0.0 is the stable baseline for where the project stands today.
- v3.0.0 is where new feature work begins (see ROADMAP.md).

## [1.0.0-alpha.1] - 2026-07-15

### Added
- Streamlit dashboard comparing Random Forest and Decision Tree predictions.
- Live packet capture tab (scapy).
- Pcap upload + analysis tab.
- Explainable AI tab (feature importance).
- `scripts/train_models.py` for CLI retraining.
- Test suite for feature-engineering logic (`tests/test_features.py`).
- Professional repo scaffolding: CI workflows, issue/PR templates, Docker support.

### Changed
- Repository restructured into `src/`, `data/`, `models/`, `docs/`, `notebooks/`, `config/` layout.
- Feature-engineering logic extracted from `app.py` into `src/nids/features.py` for testability.

### Documentation
- Added README, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, SUPPORT, RELEASE, ROADMAP.
