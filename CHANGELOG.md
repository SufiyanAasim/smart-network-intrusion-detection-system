# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [7.0.0] - 2026-07-17

### Added
- **Dashboard auth/login** (`src/nids/auth.py`) — optional PBKDF2-SHA256
  password gate. Set `NIDS_AUTH_PASSWORD_HASH` (generate with
  `python -m nids.auth`) and, optionally, `NIDS_AUTH_USERNAME`; the app then
  shows a login form and halts until authenticated, with a sidebar logout.
  Passwords are never stored or compared in plaintext; when unconfigured the
  app runs open (backward compatible).
- **Auto-block suggestion** (`src/nids/firewall.py`) — for a flagged
  attacker IP, a "🚫 Suggested block rules" expander shows ready-to-copy
  firewall commands (iptables, ufw, nftables, Windows netsh). Shown in the
  critical-threat summary and the per-IP drill-down. **Suggestion only** —
  the app never executes these commands or changes any system state; the
  operator reviews and applies them manually.
- Tests for both modules (`tests/test_auth.py`, `tests/test_firewall.py`).

### Notes
- Codename: **Bastion** (Guardian/Security theme), 2-feature release per the
  locked v4–v8 cadence (see RELEASE.md).
- No new third-party dependencies (both features are standard-library only).

## [6.0.0] - 2026-07-17

### Added
- **GeoIP + source-IP geography** (`src/nids/geo.py`) — History tab shows a
  breakdown of distinct source IPs by type (private / public / loopback /
  reserved). If `geoip2` + a MaxMind GeoLite2-City DB (`GEOIP_DB_PATH`) are
  present, public IPs are plotted on a world map; otherwise a clear caption
  explains how to enable it.
- **PDF report export** (`src/nids/reporting.py`, reportlab) — a
  "📄 Download PDF report" button beside the CSV download summarizes a
  classified batch (totals, per-model attack counts, top attacker IPs).
- **Real-time throughput graph** (`src/nids/throughput.py`) — the Live
  Capture tab shows a live packets/sec + KB/sec area chart over a rolling
  60-second window.
- **Sound / browser alert notification** (`src/nids/notify.py`) — opt-in
  sidebar toggles play a synthesized beep and/or raise a browser
  Notification on a critical threat (cooldown-throttled with existing alerts).
- **Npcap install-check banner** (`src/nids/netcheck.py`) — the Live Capture
  tab detects a missing packet-capture provider and shows a platform-specific
  fix (Npcap link on Windows), disabling "Start Capture" instead of silently
  capturing nothing.
- Tests for all five modules (`tests/test_geo.py`, `test_reporting.py`,
  `test_throughput.py`, `test_notify.py`, `test_netcheck.py`).

### Notes
- Codename: **Aegis** (Guardian/Security theme) — a **grand release**
  bundling 5 features, per the locked v4–v8 cadence (see RELEASE.md).
- New dependencies: `reportlab>=4.0` (PDF), `geoip2>=4.7` (optional GeoIP).

## [5.0.0] - 2026-07-17

### Added
- Full history export — download the **entire** persisted `data/history.db`
  as CSV or Excel (`.xlsx`) from the History tab, not just the visible
  200-row window. Via new `storage.query_all()` and an optional openpyxl
  Excel path (gracefully hidden if openpyxl isn't installed).
- Per-IP drill-down — pick a source IP on the History tab to see every past
  detection for it across sessions, plus a per-IP summary (total, RF/DT
  attack counts, first/last seen). Via new `storage.query_by_ip()`,
  `storage.query_ip_summary()`, and `storage.query_distinct_ips()`.

### Changed
- Migrated all `use_container_width=True` calls to `width='stretch'`,
  removing Streamlit's deprecation warnings from the logs.

### Notes
- Codename: **Bulwark** (Guardian/Security theme), 2-feature release per the
  locked v4–v8 cadence (see RELEASE.md).
- New dependency: `openpyxl>=3.1` (for the Excel export path).

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
