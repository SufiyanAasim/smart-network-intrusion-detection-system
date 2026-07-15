# Roadmap

## v1.0.0-alpha.1 (current)
- [x] Repo restructured to professional layout.
- [x] Feature-engineering logic extracted and unit tested.
- [x] CI (lint + test), issue/PR templates, Docker support.

## v1.0.0 (target)
- [ ] Finalize release codename/naming.
- [ ] Replace simplified live-capture feature engineering (several NSL-KDD
      fields are hardcoded/static) with fuller windowed statistics.
- [ ] Add CI job that smoke-tests `streamlit run` boots without error.
- [ ] Tag `v1.0.0` stable.

## Later
- [ ] Persist live-capture history beyond the in-memory 100-row buffer.
- [ ] Add a model-retraining CI job triggered on `data/nsl-kdd/` changes.
- [ ] Optional: add a lightweight anomaly-detection model as a third comparison column.
