# Roadmap

## v1.0.0 — Sentinel · Foundation (done)
- [x] Repo restructured to professional layout.
- [x] Feature-engineering logic extracted and unit tested.
- [x] CI (lint + test), issue/PR templates, Docker support.

## v2.0.0 — Vanguard · Baseline (done)
- [x] Tag the current working dashboard (live capture, pcap upload,
      dual-model comparison, explainable AI) as the stable starting point.

## v3.0.0 — Watchtower (done)
Shipped as one larger consolidation release rather than the standard
2-feature cadence below, since it closed out everything already in
progress before the per-release scope rule (see "Release cadence") kicked in:
- [x] Real trailing 2s/100-connection windowed feature computation.
- [x] Persistent detection history (SQLite, "📜 History" tab).
- [x] Critical-threat alerting (Slack / webhook / email), cooldown-throttled.
- [x] Third model: Isolation Forest anomaly detection alongside RF/DT.
- [x] Project logo, sidebar/header branding, custom theme.
- [x] UX: toast alerts, About panel, live packet counter, History source filter.
- [x] `docs/DATASET.md` — NSL-KDD source/citation/column documentation.
- [x] Tagged `v3.0.0`.

## Release cadence (v4.0.0–v11.0.0)

Guardian/Security codename sequence — see RELEASE.md for the full table.
Each release stays within its scope; CI/infra hardening doesn't count
against the feature quota below.

| Version | Codename | Features |
| --- | --- | --- |
| v4.0.0 | Citadel | 1) Configurable CRITICAL/SUSPICIOUS thresholds — 2) History trend chart |
| v5.0.0 | Bulwark | 1) Full history export (CSV/Excel) — 2) Per-IP drill-down |
| v6.0.0 | **Aegis** (grand) | 1) GeoIP + attacker map — 2) PDF report export — 3) Real-time throughput graph — 4) Sound/browser alert notification — 5) Npcap install-check banner |
| v7.0.0 | Bastion | 1) Dashboard auth/login — 2) Auto-block suggestion (firewall rule snippet for a flagged IP) |
| v8.0.0 | **Phalanx** (grand) | 1) Model-retraining CI pipeline — 2) Multi-user roles/permissions — 3) REST API for detections — 4) Encrypted history-db storage option — 5) Extra alert integrations (PagerDuty/Teams) |
| v9.0.0 | **Vigil** (grand) | Render deployment · mandatory production auth · lockout protection · cloud-aware capture · branded UI · consensus threat triage |
| v10.0.0 | **Argus** | Adapter selection · explicit capture scope · role-first authentication · Viewer-only sign-up · professional operations shell |
| v11.0.0 | **Cipher** | Policy-governed autonomy · correlation · drift signals · approvals · reversible containment · audit trail |

## v4.0.0 — Citadel (done)

1. [x] **Configurable thresholds** — CRITICAL threshold is now a sidebar
       slider (`⚙️ Thresholds`, default 20%, env default via
       `CRITICAL_THRESHOLD_PCT`), replacing the hardcoded constant in
       `generate_smart_summary`.
2. [x] **History trend chart** — "Attacks over time" line chart (RF vs. DT,
       per-minute buckets) on the "📜 History" tab, via `storage.query_trend()`.

## v5.0.0 — Bulwark (done)

1. [x] **Full history export** — download the entire persisted
       `data/history.db` as CSV or Excel from the History tab, via
       `storage.query_all()` (Excel path optional on `openpyxl`).
2. [x] **Per-IP drill-down** — pick a source IP to see all its past
       detections across sessions + a per-IP summary, via
       `storage.query_by_ip()` / `query_ip_summary()` / `query_distinct_ips()`.

## v6.0.0 — Aegis (done, grand release: 5 features)

1. [x] **GeoIP + source-IP geography** — IP-type breakdown + optional
       MaxMind world map (`src/nids/geo.py`).
2. [x] **PDF report export** — reportlab summary report
       (`src/nids/reporting.py`).
3. [x] **Real-time throughput graph** — live packets/sec + KB/sec chart
       (`src/nids/throughput.py`).
4. [x] **Sound / browser alert notification** — opt-in beep + desktop
       notification (`src/nids/notify.py`).
5. [x] **Npcap install-check banner** — capture-readiness detection
       (`src/nids/netcheck.py`).

## v7.0.0 — Bastion (done, 2 features)

1. [x] **Dashboard auth/login** — optional PBKDF2 password gate
       (`src/nids/auth.py`), off by default.
2. [x] **Auto-block suggestion** — copy-paste firewall rules for a flagged
       IP (`src/nids/firewall.py`), suggestion-only.

## v8.0.0 — Phalanx (done, grand release: 5 features)

1. [x] **Model-retraining CI pipeline** — `.github/workflows/retrain.yml`.
2. [x] **Multi-user roles/permissions** — admin/viewer via `NIDS_AUTH_USERS`
       (`src/nids/auth.py`).
3. [x] **REST API for detections** — `src/nids/api.py` (`python src/nids/api.py`).
4. [x] **Encrypted history-db backup** — Fernet backup (`src/nids/crypto.py`).
5. [x] **Extra alert integrations** — PagerDuty + Microsoft Teams
       (`src/nids/alerts.py`).

## v9.0.0 — Vigil (done, grand release: 6 features)

1. [x] **Render cloud-deployment configuration** — `render.yaml` blueprint with persistent disk.
2. [x] **Mandatory production login gate** — auth enforced automatically in production (e.g. on Render) to prevent public security holes.
3. [x] **Lockout rate-limiting brute-force protection** — 5-attempt limit with a 5-minute lockout in `src/nids/auth.py`.
4. [x] **Cloud-aware Live Capture** — disables live packet sniffing in cloud/Render environments (showing a warning banner) but retains PCAP upload.
5. [x] **Brand-customized login screen** — visually customized login UI matching the NIDS color theme.
6. [x] **Consensus threat triage** — cross-model 0–100 risk scoring, persisted triage queue, and filtered read-only API endpoint.

## v10.0.0 — Argus (done)

1. [x] **Capture-interface selector** — friendly Npcap/Scapy adapter choices with an optional environment default.
2. [x] **Explicit capture scope** — device visibility plus whole-LAN SPAN/TAP/gateway guidance.
3. [x] **Role-first authentication screens** — Administrator and Viewer selectors open the matching Sign in flow; Create account remains separate.
4. [x] **Viewer-only self-registration** — opt-in local SQLite store with salted PBKDF2 hashes.
5. [x] **Professional operations shell** — compact one-screen sidebar, top-bar notifications, Credits/About hierarchy, equal History cards, clean Material controls, stable verdict labels, and a concise footer.

## v11.0.0 — Cipher (done)

- Shadow, Approval, and Autonomous operating modes
- Correlated high-confidence incidents and behavior-drift signals
- Reversible, time-bound containment with server-side execution guardrails
- Administrator approvals, Viewer-readable evidence, and full audit trail

## Roadmap complete (v3.0.0 → v11.0.0)

The Guardian/Security codename sequence is fully shipped: Watchtower,
Citadel, Bulwark, Aegis, Bastion, Phalanx, Vigil, Argus, Cipher. Future work is now open-ended —
add ideas below as they come up.

## v9 audit and hardening pass (done)

A full review of every file, fixing correctness and UI/UX defects found:
- [x] Live capture is stoppable (was a blocking `while` loop).
- [x] Capture no longer wrongly disabled on Linux/macOS.
- [x] Friendly errors for corrupt/mismatched models; API 400s instead of 500s;
      `python src/nids/api.py` works as documented.
- [x] UI/UX: real sidebar metrics, one consistent model palette, human-readable
      chart axes, explained Isolation Forest omission, proper empty states.
- [x] Removed 76 MB of duplicate dataset trees (`IDS PROJECT/`, `Dataset/`).
- [x] Desktop `.exe` build (PyInstaller) + `docs/deployment/desktop-exe.md`.

## Backlog (unscheduled)
- CI job that smoke-tests `streamlit run` boots without error.
- Build the desktop `.exe` in CI and attach it to GitHub releases.
- OpenAPI schema + write endpoints for the REST API.
- Transparent (queryable) at-rest encryption, beyond the current backup option.
- Containerized deployment recipe with auth + HTTPS reverse proxy.
- Cache the fitted LabelEncoders so the app doesn't parse the 19 MB
  `KDDTrain+.txt` on every cold start (also shrinks the desktop bundle).
