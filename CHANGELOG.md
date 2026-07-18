# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbers follow the milestone scheme documented in [RELEASE.md](RELEASE.md).

## [Unreleased]

## [11.0.0] - 2026-07-18

### Added
- **Policy-governed autonomy** — Shadow, Approval, and Autonomous operating modes with a separate server-side execution gate.
- **Incident correlation** — stable per-source/time-window incidents built from configurable high-confidence model evidence.
- **Reversible containment** — validated no-shell firewall commands, private-source protection, active-block limits, TTL expiry, and Administrator rollback.
- **Autonomy persistence** — SQLite incidents, actions, and append-only audit events alongside detection history.
- **Adaptive drift monitor** — compares recent behavior with older persisted traffic and recommends reviewed offline retraining without replacing models silently.
- **Autonomous Defense workspace** — mode controls, guardrails, metrics, approval queue, containment controls, correlated incidents, and audit evidence.
- **Autonomy API** — read-only summary, incident, and action endpoints with bounded filters.

### Changed
- Bumped package, API, image, Compose, feature contract, documentation, and release checks to `11.0.0`.
- Standardized the current release identity as **Cipher v11.0.0** and recorded v10.0.0 as **Argus**.
- Standardized the human-facing product name as **Smart Network Intrusion Detection System** and re-spaced the sidebar into clear Access, model-accuracy, and threshold sections.
- Split monitoring into a default Dashboard and a dedicated Live Capture view; moved the technology list into About to keep Credits compact.
- Left-aligned the shared About/Role Permissions identity block and precisely centered the Live Capture recorder with the title across light and dark themes.
- Made Credits spacing viewport-aware: compact no-scroll composition on shorter displays and more generous section/card rhythm on taller screens, while keeping contributor avatars close to their identities.
- Returned the 60-second throughput monitor to Live Capture and replaced the Dashboard's duplicated live charts with session-level triage, model-rate, risk-distribution, and source analytics.
- Clarified sidebar control state with a percentage-formatted threshold, an explicit all-models-active indicator, grouped access controls, and a bottom-anchored Logout action; range details now remain in the slider interaction instead of duplicate static labels.
- Removed the redundant role badge from the Live Capture action header; the grouped Sidebar Access card is now the single non-clickable source of role identity.
- Removed Auto rerun and transient file-change status from unauthenticated Sign in/Create account views, and added a consistent 22px brand-to-navigation gap.
- Restored throughput and detailed model-result graphs to Live Capture, moved Print beside Record Screen there, stabilized capture reruns with fixed status/chart regions, and standardized action labels to Title Case.
- Moved Prepare Report Exports into the Dashboard header action slot with the same cyan treatment and dimensions as Record Screen, while keeping generated downloads in the dashboard body.
- Normalized the four dashboard analytics charts onto an equal two-column grid, reduced the triage donut radius to protect its legend, and moved the source-risk legend below its plot for matched chart widths.
- Matched the Live Capture Print and Record Screen controls, tightened the throughput-to-divider spacing, removed report-export controls from live model results, and replaced missing evaluation data's misleading `0.0%` fallback with `Not measured`.
- Standardized the PCAP uploader to a 56px dropzone with a vertically centered 40px Upload action and equal vertical padding.
- Reworked the sidebar onto a 28px section rhythm with compact accuracy cards, balanced 13px/16px typography, a heading-aligned teal threshold value, and no floating slider value label.
- Isolated timed capture into a fixed-height packet-counter fragment plus a separate height-reserved throughput fragment; both update live without collapsing the page or flashing its scrollbar, while heavier model evidence remains stable until Start/Stop transitions.
- Grouped Deploy and Streamlit's running-status indicator beside the hamburger on Sign In and Sign Up only, without changing the authenticated application toolbar.
- Fixed the Access card overlap by reserving the identity block's rendered height and a 10px permission-action gap, then normalized native application actions to a shared 40px control height.
- Added metric-style bordered surfaces to all four dashboard analytics charts, restored natural chart sizing with matched row minimums so Source IP labels remain readable, and restored the borderless compact footer across every application tab.
- Replaced the filled role identity surface with a centered cyan-outlined Administrator/Viewer pill, keeping the signed-in identity and Role Permissions on neutral surrounding surfaces.
- Rebuilt the sidebar on an 8px spacing grid with equal 32px section rhythm, 8px model-row gaps, a 24px threshold-to-Logout gap, and shared Access/Logout grid lines.
- Live and uploaded evidence now enters the autonomy correlation pipeline after immutable model verdicts and consensus triage are persisted.

### Security
- Shadow mode and host execution disabled are the defaults across local, Docker, Compose, and Render configuration.
- Autonomous execution requires explicit server policy, validates every IP, protects private sources by default, never invokes a shell, limits active blocks, and records failures without interrupting detection.

### Notes
- Codename: **Cipher** — the policy-governed autonomy release.

## [10.0.0] - 2026-07-18

### Added
- **Capture interface selector** — lists Scapy/Npcap adapters with friendly names and addresses, honours `NIDS_CAPTURE_INTERFACE`, locks the selection while capture is active, and passes the chosen adapter to `sniff()`.
- **Capture-scope guidance** — distinguishes traffic visible to this device from whole-LAN monitoring and documents SPAN/port mirroring, TAP, and gateway sensor options.
- **Role-first authentication** — dedicated Sign in and Create account views; clickable Administrator and Viewer selectors open the matching credential form.
- **Viewer-only self-registration** — optional `NIDS_SIGNUP_ENABLED` flow backed by a salted PBKDF2 account store at `NIDS_AUTH_DB_PATH`; public users cannot create Administrator accounts.
- **Application footer** — concise product identity, local-capture reminder, and project link without duplicating release metadata.
- **Release consistency gate** — CI now fails if runtime, Docker, Compose, README, API, feature schema, release notes, codenames, or active docs drift from v10.0.0.
- **Explicit report preparation** — Stop Capture only pauses packet intake; CSV, PDF, and Print controls appear only after the operator selects **Prepare report exports**.
- **Professional operations shell** — compact one-screen sidebar, top-bar notification controls, a first-class Credits tab, Credits-to-About dialog flow, and equal-size History metrics.

### Changed
- Bumped the package, API, image, feature contract, and documentation to `10.0.0`; Compose now uses the version-neutral `nids-history` volume with an upgrade override.
- Standardized the release identity as **Argus v10.0.0**.
- Reserved the full product hero for Credits to remove repeated branding from operational views, and refined sidebar, contributor, and authentication layouts for responsive light and dark themes.
- Replaced Streamlit's vertical-ellipsis menu treatment with an enclosed hamburger symbol and removed the intrusive “Press Enter to submit form” hint.
- Slowed visible live-dashboard refreshes to a configurable 2.5-second minimum so active capture remains readable without changing packet analysis semantics.
- Docker/Render definitions now expose a persistent authentication database path while Render keeps self-registration explicitly disabled.
- Replaced decorative emoji controls and verdicts with Material icons and clean `Normal`/`Attack` labels; existing history is normalized automatically on database open.
- Moved Notifications beside the deployment toolbar, moved Credits beside History, and relocated About inside Credits to remove duplicate navigation.
- Reserved separate toolbar lanes for Streamlit's running activity indicator, file-change controls, Deploy, Notifications, and the hamburger menu so transient controls never overlap.
- Restored Streamlit's running-person activity indicator, removed its duplicate header Stop action, kept Auto rerun available in the hamburger menu, and hid only the duplicated manual Rerun entry.
- Moved the active Administrator/Viewer/Local Owner badge out of the Credits hero and into the Live Capture title row, aligned directly above Stop Capture.
- Matched the live role badge to the Stop Capture column width for stable Administrator/Viewer alignment, enlarged the Credits logo, and italicized its supporting product description.
- Replaced temporary instant role access with mandatory role-first credential forms, and standardized the larger logo/title grid in the About and Access dialogs.
- Added Data Sciences and Cybersecurity domain pills to contributor cards and condensed each contributor's responsibilities into two focused lines.

### Security
- Self-registration is opt-in, creates Viewers only, validates strong passwords, rejects configured-name collisions case-insensitively, and never stores plaintext credentials.
- Administrator provisioning remains configuration-only; production sign-up is disabled by default.

### Notes
- Codename: **Argus** (Guardian/Security theme) — the capture, control, and verify release.

## [9.0.0] - 2026-07-17

### Added
- **Render Cloud Deployment** (`render.yaml`) — a Render blueprint specifying a persistent volume for the SQLite database.
- **Mandatory Production Login Gate** (`src/nids/app.py`) — enforces the login gate on Render automatically.
- **Brute-Force Lockout Protection** (`src/nids/auth.py`) — 5-failed-attempt lockout (5 minutes) to protect public dashboards.
- **Cloud-Aware Live Capture** (`src/nids/netcheck.py`) — disables live capture on Render (showing warning banner) but keeps PCAP upload.
- **Brand-Customized Login UI** (`src/nids/app.py`) — visually polished login form with NIDS logo branding.
- **Consensus Threat Triage** (`src/nids/triage.py`) — deterministic model-vote risk scoring, a dashboard triage queue, persisted risk fields, and the filtered `GET /api/triage` endpoint.

### Changed
- Bumped package version variable to `9.0.0`.
- Replaced the previous shield with the canonical transparent circuit-shield logo and synchronized the Windows multi-resolution icon.
- Refined hero and dialog alignment, added GitHub profile images to contributor cards, and made admin/viewer access discoverable through persistent role badges and an in-app permission matrix.
- Added automatic, non-overriding `.env` loading for local source runs so admin/viewer accounts work without manually exporting environment variables.
- Added separate light/dark palettes and adaptive dashboard surfaces, then refined the header hierarchy, metric cards, and batch-level consensus summary.
- Standardized the product name as **Smart Network Intrusion Detection System**, changed
  the active interface codename from Sentinel to **Vigil**, and replaced the
  inline About/Credits sections with accessible modal dialogs and contributor links.
- Hardened and versioned the container stack: non-root/read-only runtime,
  dynamic health checks, persistent history, opt-in API and Linux capture
  profiles, Render Starter disk compatibility, and image health smoke tests.
- Upgraded GitHub Actions and Dependabot configuration and added repository-wide
  YAML linting for deployment, workflow, and application configuration.

### Fixed
- Replaced non-ASCII characters in `scripts/build_exe.py` to prevent UnicodeEncodeError crashes on standard Windows consoles.
- PCAP identity now uses a content hash, so two different same-name uploads cannot reuse stale results; oversized captures are rejected at 50 MB.
- Live capture permission/backend failures now stop the capture cleanly with an actionable message instead of crashing the Streamlit run.
- Unknown categorical values now map to a deterministic encoder class rather than an unordered set element.
- Existing v8 SQLite databases migrate in place to the v9 triage schema; relative DB paths, NaN numeric fields, and concurrent waits are handled safely.
- IPv6 response snippets now use `ip6tables` and the nftables `ip6` family.
- Invalid multi-user JSON, roles, duplicates, or hash shapes fail closed in the UI; hostile PBKDF2 iteration counts are rejected before hashing.
- Corrected the documented cross-platform API/auth entry points and v8 API response examples.
- Corrected Windows capture guidance so Administrator is only required when Npcap access is restricted.

### Notes
- Codename: **Vigil** (Guardian/Security theme) — the deploy release.


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
- **The documented API entry point failed from the repo root.** The supported
  cross-platform command is now `python src/nids/api.py`, which bootstraps
  `src/` before importing the package.
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
  `/api/detections`, `/api/ip/<ip>`), run via `python src/nids/api.py`. Optional
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
- Codename: **Phalanx** (Guardian/Security theme) — the final **grand
  release** (5 features) of the v3–v8 roadmap. See RELEASE.md.
- New dependency: `cryptography>=42.0` (encrypted backup).

## [7.0.0] - 2026-07-17

### Added
- **Dashboard auth/login** (`src/nids/auth.py`) — optional PBKDF2-SHA256
  password gate. Set `NIDS_AUTH_PASSWORD_HASH` (generate with
  `python src/nids/auth.py`) and, optionally, `NIDS_AUTH_USERNAME`; the app then
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
- `assets/images/logo.png` — a Guardian/Security-themed shield logo, shown
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
  release, except v6.0.0 (Aegis), v8.0.0 (Phalanx) and v9.0.0 (Vigil) which are grand
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

## [1.0.0] - 2026-07-15

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
