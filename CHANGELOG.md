# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
