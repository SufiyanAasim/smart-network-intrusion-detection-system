# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- **Live capture could not be stopped.** The capture ran in a blocking
  `while` loop, so Streamlit never got control back to process the
  "⏹️ Stop Capture" click. Capture now processes one batch per script run and
  reruns, keeping every widget responsive.
- **Live capture was wrongly disabled on Linux/macOS.** `netcheck` gated the
  Start button on scapy's `conf.use_pcap`, but scapy captures through native
  raw sockets there (with `use_pcap` False) — only Windows actually needs
  Npcap. A platform-appropriate privilege hint is shown instead.
- **Corrupt/mismatched model files showed a raw traceback.** `load_resources`
  only caught `FileNotFoundError`; it now explains a scikit-learn version
  mismatch and points at `scripts/train_models.py`.
- **`python -m nids.api` failed from the repo root** as documented — `api.py`
  now bootstraps `src/` onto `sys.path` like the other entry points.
- **REST API returned 500 on a bad `?limit=`.** Non-numeric and out-of-range
  values now return 400, and `limit` is capped (`MAX_LIMIT`). `/api/ip/<ip>`
  percent-decodes its argument and rejects an empty IP.
- Download buttons now carry explicit widget keys (they render in more than
  one tab, risking duplicate element IDs).
- `display_results` no longer swallows diagnostics into a bare `Error: …`.
- **History tab crashed when the database sat on another drive.** It labelled
  the DB with `os.path.relpath(db, BASE_DIR)`, which raises `ValueError` on
  Windows across drives — exactly the packaged build's layout (history under
  `%LOCALAPPDATA%` on `C:`, app on `D:`), and any `NIDS_DB_PATH` on a
  different volume. Caught by running the built `.exe`.
- **The packaged app hung on first launch.** Streamlit's "Welcome to
  Streamlit! … Email:" onboarding prompt blocks on stdin, which a
  double-clicked `.exe` can never answer; the launcher now opts out. It also
  forwards CLI flags to Streamlit instead of discarding them.

### Changed (UI/UX)
- **Sidebar accuracies are real metrics**, not `st.info`/`st.warning`/
  `st.success` boxes — a healthy Decision Tree score sat in a yellow
  "warning" box that read as an alarm, and those colours contradicted the
  charts.
- **One palette across the app** (`COLOR_RF`/`COLOR_DT`/`COLOR_IFOREST`), so a
  model reads as the same colour in the sidebar, its results column and the
  Explainable AI charts.
- **Live throughput plots "seconds ago"** instead of a raw epoch-second axis
  (`1721208000` meant nothing to a viewer).
- **History trend uses a real temporal axis**; the nominal per-minute axis
  became unreadable as history grew.
- **Explainable AI explains the missing third model** rather than silently
  showing only RF/DT (Isolation Forest exposes no `feature_importances_`).
- Upload tab points at the bundled sample pcaps; Live Capture has proper
  idle/waiting/paused states; Stop is disabled when idle.
- Charts gained axis titles/units and lost redundant legends.

### Added
- **Desktop executable** — `scripts/desktop_launcher.py` + `nids.spec` +
  `scripts/build_exe.py` produce `dist/NIDS/NIDS.exe`. See
  [docs/deployment/desktop-exe.md](docs/deployment/desktop-exe.md).
- `NIDS_DB_PATH` overrides the history-database location (required for the
  packaged build, whose bundle dir is read-only and wiped on exit).

### Removed
- `IDS PROJECT/` and `Dataset/` — 76 MB of byte-identical duplicates of
  `data/nsl-kdd/`, verified by checksum and referenced nowhere.

## [8.0.0] - 2026-07-17

### Added
- **Model-retraining CI pipeline** (`.github/workflows/retrain.yml`) —
  retrains the models when `data/nsl-kdd/`, `scripts/train_models.py`, or
  `src/nids/features.py` change on `main` (or on demand), sanity-checks that
  the models load, and uploads them as artifacts. New `make api` target.
- **Multi-user roles/permissions** (`src/nids/auth.py`) — configure several
  users with roles via `NIDS_AUTH_USERS` (JSON). `admin` sees everything;
  `viewer` is blocked from admin-only actions (full-history/encrypted
  export). Single-user setup stays backward compatible (treated as admin),
  and an open app grants full access.
- **REST API for detections** (`src/nids/api.py`) — a dependency-free,
  read-only JSON API over the history DB (`/health`, `/api/summary`,
  `/api/detections`, `/api/ip/<ip>`), run via `python -m nids.api`. Optional
  bearer-token auth via `NIDS_API_TOKEN`.
- **Encrypted history-db backup** (`src/nids/crypto.py`) — download a
  Fernet-encrypted (`cryptography`) backup of `data/history.db` from the
  History tab when `NIDS_DB_ENCRYPTION_KEY` is set.
- **Extra alert integrations** (`src/nids/alerts.py`) — PagerDuty (Events
  API v2, `PAGERDUTY_ROUTING_KEY`) and Microsoft Teams
  (`TEAMS_WEBHOOK_URL`), folded into `send_critical_alert`.
- Tests for all five (`tests/test_api.py`, `test_crypto.py`,
  `test_auth_roles.py`, `test_alerts_extra.py`).

### Notes
- Codename: **Cipher** (Guardian/Security theme) — the final **grand
  release** (5 features) of the v3–v8 roadmap. See RELEASE.md.
- New dependency: `cryptography>=42.0` (encrypted backup).

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
