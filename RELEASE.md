# Release Process

## Versioning (this project's scheme)

This project uses major-version milestones rather than strict semver
breaking-change semantics:

```
v1.0.0   pre-release — repo restructure, docs, CI, test scaffolding
v2.0.0   stable release — the working dashboard as it stands today
v3.0.0+  active feature development going forward
```

Within each major milestone, standard `MINOR.PATCH` rules still apply:
- **Minor** — new functionality, backward compatible.
- **Patch** — bug fixes only.
- Pre-release identifiers (`-alpha.1`, `-beta.1`, `-rc.1`) are used before a
  major milestone is cut stable.

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
