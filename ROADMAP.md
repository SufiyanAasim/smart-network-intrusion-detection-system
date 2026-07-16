# Roadmap

## v1.0.0-alpha.1 — Sentinel · Foundation (done)
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

## Release cadence (locked, v4.0.0–v8.0.0)

Guardian/Security codename sequence — see RELEASE.md for the full table.
Each release stays within its scope; CI/infra hardening doesn't count
against the feature quota below.

| Version | Codename | Features |
| --- | --- | --- |
| v4.0.0 | Citadel | 1) Configurable CRITICAL/SUSPICIOUS thresholds — 2) History trend chart |
| v5.0.0 | Bulwark | 1) Full history export (CSV/Excel) — 2) Per-IP drill-down |
| v6.0.0 | **Aegis** (grand) | 1) GeoIP + attacker map — 2) PDF report export — 3) Real-time throughput graph — 4) Sound/browser alert notification — 5) Npcap install-check banner |
| v7.0.0 | Bastion | 1) Dashboard auth/login — 2) Auto-block suggestion (firewall rule snippet for a flagged IP) |
| v8.0.0 | **Cipher** (grand) | 1) Model-retraining CI pipeline — 2) Multi-user roles/permissions — 3) REST API for detections — 4) Encrypted history-db storage option — 5) Extra alert integrations (PagerDuty/Teams) |

## v4.0.0 — Citadel (next)

1. **Configurable thresholds** — CRITICAL (currently hardcoded ≥20%) and
   SUSPICIOUS (>0%) cutoffs become adjustable via a sidebar slider (and/or
   `.env` defaults), instead of fixed constants in `generate_smart_summary`.
2. **History trend chart** — a time-series chart on the "📜 History" tab
   (attacks vs. normal over time), not just the current flat table.

## Infra (not counted against feature quota, pick up opportunistically)
- [ ] CI job that smoke-tests `streamlit run` boots without error.
- [ ] Model-retraining CI job triggered on `data/nsl-kdd/` changes (pulled
      forward into v8.0.0 as a full pipeline, but a simpler CI check could
      land earlier).
