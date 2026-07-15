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
