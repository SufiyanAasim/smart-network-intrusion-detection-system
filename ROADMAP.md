# Roadmap

## v1.0.0-alpha.1 — pre-release (done)
- [x] Repo restructured to professional layout.
- [x] Feature-engineering logic extracted and unit tested.
- [x] CI (lint + test), issue/PR templates, Docker support.

## v2.0.0 — stable baseline (current)
- [x] Tag the current working dashboard (live capture, pcap upload,
      dual-model comparison, explainable AI) as the stable starting point.
- [ ] Finalize release codename/naming for v1.0.0 and v2.0.0.

## v3.0.0 — active feature development (in progress)
- [x] Replace simplified live-capture feature engineering with a real
      trailing 2s/100-connection windowed computation.
- [x] Persist detection history beyond the in-memory 100-row buffer
      (SQLite, `src/nids/storage.py`, "📜 History" tab).
- [x] Critical-threat alerting (Slack / webhook / email), cooldown-throttled.
- [x] Third model: Isolation Forest anomaly detection alongside RF/DT.
- [ ] Add CI job that smoke-tests `streamlit run` boots without error.
- [ ] Tag `v3.0.0` once the above is verified end-to-end.

## Later
- [ ] Add a model-retraining CI job triggered on `data/nsl-kdd/` changes.
- [ ] Auth/access control if the dashboard is deployed beyond localhost.
- [ ] PDF/report export in addition to CSV download.
