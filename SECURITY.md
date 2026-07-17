# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 7.x | ✅ |
| 3.x – 6.x | ✅ |
| < 3.0 | ❌ |

## Reporting a vulnerability

Do not open a public GitHub issue for security vulnerabilities. Instead,
email the security maintainer directly:

**Muhammad Taha Siddiqui** ([@13eeCoder](https://github.com/13eeCoder)) —
tahasiddiqui2100@gmail.com
(CC sufiyanaasim@outlook.com for anything affecting the models, build or release.)

Include:

- A description of the issue and its impact.
- Steps to reproduce.
- Affected version/commit.

Expect an acknowledgement within a few days.

## Notes on this project's threat model

- The live-capture feature requires raw-socket access; only run it in
  environments you trust and control.
- Uploaded `.pcap` files are parsed with scapy and deleted after processing —
  do not upload files from untrusted sources on a shared/multi-tenant deployment.
- Model files (`models/*.pkl`) are loaded with `joblib.load`, which can
  execute arbitrary code if the file is tampered with. Only load models
  from this repository or a trusted source.

## Dashboard login

- Login is **optional** and off by default; when unconfigured the dashboard
  is open to anyone who can reach it. Enable it (set
  `NIDS_AUTH_PASSWORD_HASH`) before exposing the app beyond localhost.
- Passwords are stored only as PBKDF2-SHA256 hashes (`src/nids/auth.py`,
  260k iterations, per-hash random salt) and compared in constant time.
  Plaintext passwords are never written to disk or logs.
- The login is a lightweight gate suitable for small/internal deployments,
  not a full identity solution. For anything internet-facing, put the app
  behind a real reverse proxy / SSO and use HTTPS.

## Auto-block suggestions

- The "Suggested block rules" feature only *displays* firewall commands for
  an operator to review and run manually. The application never executes
  them, opens privileged sockets, or modifies firewall/system state.

## Roles, REST API, and encrypted backup (v8.0.0)

- **Roles:** with `NIDS_AUTH_USERS`, `viewer` accounts are blocked from
  admin-only actions (full-history and encrypted export). This is
  UI-level access control, not a security boundary against a determined
  user who can reach the server — pair it with network controls.
- **REST API:** read-only. Set `NIDS_API_TOKEN` and keep it bound to
  localhost (or behind a proxy) if the history contains sensitive IPs. It
  ships no write endpoints.
- **Encrypted backup:** the "Encrypted backup" download is Fernet
  (AES-128-CBC + HMAC) via the `cryptography` package, keyed by
  `NIDS_DB_ENCRYPTION_KEY`. This protects the *exported backup file* at
  rest; the live `data/history.db` itself is still plaintext SQLite. Store
  the key separately from the backups.
