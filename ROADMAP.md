# Roadmap

## v1.0.0-alpha.1 — Sentinel · Foundation (done)
- [x] Repo restructured to professional layout.
- [x] Feature-engineering logic extracted and unit tested.
- [x] CI (lint + test), issue/PR templates, Docker support.

## v2.0.0 — Vanguard · Baseline (done)
- [x] Tag the current working dashboard (live capture, pcap upload,
      dual-model comparison, explainable AI) as the stable starting point.

## v3.0.0 — Watchtower (current)
Shipped as one larger consolidation release rather than the standard
2-feature cadence below, since it closed out everything already in
progress before the per-release scope rule (see "Release cadence") kicked in:
- [x] Real trailing 2s/100-connection windowed feature computation
      (replacing the hardcoded single-packet approximation).
- [x] Persistent detection history (SQLite, `src/nids/storage.py`, "📜 History" tab).
- [x] Critical-threat alerting (Slack / webhook / email), cooldown-throttled.
- [x] Third model: Isolation Forest anomaly detection alongside RF/DT.
- [x] Project logo, sidebar/header branding, custom theme.
- [x] UX: toast alerts, About panel, live packet counter, History source filter.
- [x] `docs/DATASET.md` — NSL-KDD source/citation/column documentation.
- [ ] Add CI job that smoke-tests `streamlit run` boots without error.
- [ ] Tag `v3.0.0` once the above is verified end-to-end.

## Release cadence (v4.0.0 onward)

Locked in for the Guardian/Security codename sequence — see RELEASE.md for
the full table:

| Version | Codename | Scope |
| --- | --- | --- |
| v4.0.0 | Citadel | 2 new features |
| v5.0.0 | Bulwark | 2 new features |
| v6.0.0 | Aegis | **5 new features (grand release)** |
| v7.0.0 | Bastion | 2 new features |
| v8.0.0 | Cipher | **5 new features (grand release)** |

Each release should stay within its scope rather than accumulating extra
work — that's what keeps the 2-feature releases fast and the grand releases
(Aegis, Cipher) meaningfully bigger by comparison.

## v4.0.0 — Citadel (next, 2 features — not yet chosen)

Candidates to pick from (see also "UX ideas" below):
- [ ] CI job that smoke-tests `streamlit run` boots without error.
- [ ] Configurable CRITICAL/SUSPICIOUS thresholds (currently hardcoded
      0%/20%) via `.env` or a sidebar slider.
- [ ] Historical trend chart on the History tab (attacks over time).
- [ ] Per-IP drill-down: click a flagged `src_ip` to see its past detections.

## UX ideas under consideration (not yet scheduled to a version)
- PDF/report export in addition to CSV download.
- Sound/browser-notification option for critical alerts, beyond the in-page toast.
- Windows Npcap install-check banner with a link to the installer, instead of only failing silently.
- Model-retraining CI job triggered on `data/nsl-kdd/` changes.
- Auth/access control if the dashboard is deployed beyond localhost.
