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

Theme: **Guardian / Security**. Each stable release gets a codename from
this theme only (never mixed with another theme). Format:

```
🚀 NIDS vX.Y.Z
Codename: <Theme Name> — <Title>
```

| Version | Codename | Title | Feature scale |
| --- | --- | --- | --- |
| v1.0.0-alpha.1 | Sentinel | Foundation | — (restructure/docs/CI) |
| v2.0.0 | Vanguard | Baseline | — (baseline tag) |
| v3.0.0 | Watchtower | *(pending title)* | 2 new features |
| v4.0.0 | Citadel | *(pending title)* | 2 new features |
| v5.0.0 | Bulwark | *(pending title)* | 2 new features |
| v6.0.0 | Aegis | *(pending title)* | **5 new features (grand release)** |
| v7.0.0 | Bastion | *(pending title)* | 2 new features |
| v8.0.0 | Cipher | *(pending title)* | **5 new features (grand release)** |

This sequence (v3–v8) was decided upfront so the codename theme stays
consistent and each release's scope is set before work starts: v3, v4, v5,
and v7 are regular 2-feature releases; v6 (Aegis) and v8 (Cipher) are grand
releases that bundle 5 new features each. Titles are chosen per-release
when its scope is finalized (see docs/releases/).

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
