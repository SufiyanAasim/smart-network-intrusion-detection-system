# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.0.x (pre-release) | ✅ |
| < 1.0 | ❌ |

## Reporting a vulnerability

Do not open a public GitHub issue for security vulnerabilities. Instead,
email the maintainer directly (see [SUPPORT.md](SUPPORT.md)) with:

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
