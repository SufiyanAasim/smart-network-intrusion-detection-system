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
⚡ Smart Network Intrusion Detection System vX.Y.Z
Codename: <Theme Name> — <Title>
```

| Version | Codename | Features |
| --- | --- | --- |
| v1.0.0 | Sentinel | — (restructure/docs/CI) |
| v2.0.0 | Vanguard | — (baseline tag) |
| v3.0.0 | Watchtower | Windowed capture, persistence, alerting, 3rd model, UX/branding (consolidation release) |
| v4.0.0 | Citadel | 1) Configurable thresholds — 2) History trend chart |
| v5.0.0 | Bulwark | 1) Full history export — 2) Per-IP drill-down |
| v6.0.0 | **Aegis** | **5 features:** GeoIP map, PDF export, throughput graph, sound alerts, Npcap install banner |
| v7.0.0 | Bastion | 1) Dashboard auth/login — 2) Auto-block suggestion |
| v8.0.0 | **Phalanx** | **5 features:** retraining pipeline, multi-user roles, REST API, encrypted storage, extra alert integrations |
| v9.0.0 | **Vigil** | **6 features:** Render deployment, mandatory login gate, lockout protection, cloud-aware capture, branded UI, consensus threat triage |
| v10.0.0 | **Argus** | Adapter selection, capture scope, role-first auth, Viewer sign-up, professional operations shell |
| v11.0.0 | **Cipher** | Policy-governed autonomy, correlation, drift signals, approvals, reversible containment, audit trail |

The v3–v9 sequence was decided upfront so the codename theme stays
consistent and each release's scope is fixed before work starts: v4, v5,
and v7 are regular 2-feature releases; v6 (Aegis), v8 (Phalanx) and v9 (Vigil) are larger
releases (v9 includes the post-audit consensus extension). v10 (Argus) is the
local-capture, access, and interface milestone; v11 (Cipher) is the
policy-governed autonomy milestone. Full detail per release is in
ROADMAP.md and, once shipped, `docs/releases/vX.Y.Z.md`.

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
