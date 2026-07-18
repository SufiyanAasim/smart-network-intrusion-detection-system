# Roadmap

## v1.0.0-alpha.1 — pre-release (done)
- [x] Repo restructured to professional layout.
- [x] Feature-engineering logic extracted and unit tested.
- [x] CI (lint + test), issue/PR templates, Docker support.

## v2.0.0 — stable baseline (current)
- [x] Tag the current working dashboard (live capture, pcap upload,
      dual-model comparison, explainable AI) as the stable starting point.
- [ ] Finalize release codename/naming for v1.0.0 and v2.0.0.

## v3.0.0 — active feature development (next)
- [ ] Replace simplified live-capture feature engineering (several NSL-KDD
      fields are hardcoded/static) with fuller windowed statistics.
- [ ] Add CI job that smoke-tests `streamlit run` boots without error.
- [ ] New features to be decided.

## Later
- [ ] Persist live-capture history beyond the in-memory 100-row buffer.
- [ ] Add a model-retraining CI job triggered on `data/nsl-kdd/` changes.
- [ ] Optional: add a lightweight anomaly-detection model as a third comparison column.
