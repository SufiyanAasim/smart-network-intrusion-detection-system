# Contributing

## Branching

- `main` — stable, always deployable.
- `develop` — integration branch for the next release.
- `feature/<name>`, `bugfix/<name>`, `hotfix/<name>`, `docs/<name>`,
  `refactor/<name>`, `test/<name>`, `ci/<name>`, `perf/<name>`,
  `security/<name>`, `experimental/<name>` — branch off `develop`
  (or `main` for `hotfix/*`).

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(app): add live-capture pause/resume
fix(features): handle UDP packets with no dst port
docs(readme): clarify docker instructions
```

Types: `feat`, `fix`, `docs`, `refactor`, `perf`, `style`, `build`, `ci`, `test`, `chore`, `revert`.

## Pull requests

- Fill in `.github/PULL_REQUEST_TEMPLATE.md`.
- Keep PRs scoped to one change.
- Run `pytest -q` and `ruff check src tests scripts` before opening.

## Local setup

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Release flow

`feature/*` → `develop` → `release/vX.Y.Z` → `main` → tag `vX.Y.Z`.
See [RELEASE.md](RELEASE.md).

## Maintainers & Code Division

The project code is divided by maintainer expertise:
- **Mohammad Sufiyan Aasim** ([@SufiyanAasim](https://github.com/SufiyanAasim) · `sufiyanaasim@outlook.com`): Data Science, ML Models (`models/`, `train_models.py`, `anomaly.py`), Dashboard (`app.py`), Triage & Consensus (`triage.py`), Storage & API (`storage.py`, `api.py`), Reporting (`reporting.py`), and MLOps/CI/Builds.
- **Muhammad Taha Siddiqui** ([@13eeCoder](https://github.com/13eeCoder) · `tahasiddiqui2100@gmail.com`): Networking & Packet Capture (`features.py`, `netcheck.py`, `throughput.py`, `geo.py`), Security & Access Controls (`auth.py`, `crypto.py`), Alerting & Notifications (`alerts.py`, `notify.py`), and Containment/Firewall (`firewall.py`).
