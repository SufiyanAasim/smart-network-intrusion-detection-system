# Release Process

## Versioning

Semantic Versioning (`MAJOR.MINOR.PATCH`), plus pre-release identifiers
during the run-up to a stable release:

```
1.0.0-alpha.1   pre-release, unstable, naming/scope still open
1.0.0-beta.1    feature-complete, stabilizing
1.0.0-rc.1      release candidate
1.0.0           first stable release
```

- **Major** — breaking changes (feature schema, model I/O contract, CLI/API).
- **Minor** — new functionality, backward compatible.
- **Patch** — bug fixes only.

## Release naming

Each stable release gets a codename from one theme (chosen once, not mixed).
Format:

```
🚀 NIDS vX.Y.Z
Codename: <Theme Name> — <Title>
```

The codename/title for v1.0.0 is not finalized yet — tracked in
[docs/releases/](docs/releases/).

## Branch flow

```
feature/*  →  develop  →  release/vX.Y.Z  →  main  →  tag vX.Y.Z
                                    ↑
                              hotfix/* (from main)
```

## Steps

1. Cut `release/vX.Y.Z` from `develop`.
2. Update `CHANGELOG.md` under `[X.Y.Z] - YYYY-MM-DD`.
3. Add a release note in `docs/releases/vX.Y.Z.md`.
4. Merge into `main`, tag `vX.Y.Z`, merge back into `develop`.
5. Publish the GitHub release using the note from step 3.

## Release cycle

```
Development → Alpha → Beta → Release Candidate → Stable → Patch → Maintenance → LTS
```
