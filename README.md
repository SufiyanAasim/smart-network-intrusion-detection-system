<div align="center">

<img src="assets/images/logo.svg" alt="NIDS Logo" width="110" />

# Network Analysis Intrusion System

**A Streamlit intrusion-detection dashboard that runs three ML models against the same live or captured traffic — side by side**

[![Python 3.11](https://img.shields.io/badge/Python-3.11%2B-3776ab?style=flat&logo=python&logoColor=white)](docs/guides/running-locally.md)
[![Version](https://img.shields.io/badge/version-8.0.0%20Cipher-8b5cf6?style=flat)](docs/releases/v8.0.0.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=flat)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%C2%B7%20Linux%20%C2%B7%20macOS-64748b?style=flat)]()
[![Tests](https://img.shields.io/badge/tests-84%20passing-16a34a?style=flat)](tests/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-0ea5e9?style=flat)](CONTRIBUTING.md)

Sniff live packets or drop in a Wireshark capture, and watch Random Forest, Decision Tree and Isolation Forest disagree in real time — with alerting, history and a REST API.

[**Desktop .exe**](docs/deployment/desktop-exe.md) · [**Changelog**](CHANGELOG.md) · [**Roadmap**](ROADMAP.md) · [**Report a Bug**](.github/ISSUE_TEMPLATE/bug_report.md)

</div>

---

## ✨ Features

### 🧠 Three-Model Comparison
- **Random Forest** — supervised ensemble trained on labelled NSL-KDD attacks (77.1% test accuracy)
- **Decision Tree** — a single interpretable tree, same feature set (78.9%)
- **Isolation Forest** — *unsupervised*, trained only on normal traffic so it flags outliers the supervised pair never learned (80.0%)
- All three classify the **same packets simultaneously** — their disagreements are the interesting part

### 📡 Live Capture
- Real-time scapy sniffing with a **true trailing 2-second / 100-connection window** for `count`, `srv_count` and the `*_rate` features — not a per-packet snapshot
- Live packets/sec + KB/sec throughput chart over a rolling 60-second window
- Capture-readiness detection: warns about a missing **Npcap** driver on Windows instead of silently capturing nothing

### 📂 Pcap Upload
- Drop a `.pcap`/`.pcapng` from Wireshark and get an instant classified report
- Three sample captures bundled in `data/pcaps/` (DDoS, Neptune, mixed)

### 📊 Visual Analytics
- Threat distribution, packet-size box plots, and an interactive log-log volume-vs-size scatter — per model
- **Explainable AI** tab: top-10 feature importances for RF/DT (and why Isolation Forest has none)

### 🔔 Alerting
- **Slack**, generic **webhook**, **email** (SMTP), **PagerDuty** (Events API v2) and **Microsoft Teams**
- Opt-in in-browser **beep** (synthesized at runtime — no audio asset) and **desktop notification**
- Cooldown-throttled per model so a sustained attack can't spam every rerun

### 📜 Persistent History & Analytics
- Every detection persisted to SQLite, far beyond the 100-row live view
- Attacks-over-time trend chart, source filter, and **per-IP drill-down** across sessions
- **Source-IP geography** breakdown (private/public/loopback/reserved) with an optional MaxMind world map

### 📤 Export
- **CSV**, **Excel**, formatted **PDF** report, and a **Fernet-encrypted backup** of the history database

### 🔒 Access Control & Response
- Optional **PBKDF2-SHA256 login** (off by default) with multi-user **admin/viewer roles**
- **Block suggestions** — copy-paste iptables / ufw / nftables / netsh rules for a flagged attacker (never auto-applied)

### 🔌 REST API
- Dependency-free read-only JSON API over the history DB, with optional bearer-token auth

---

## 🏗️ Architecture

```
   data/nsl-kdd/  ──(train)──►  scripts/train_models.py  ──►  models/*.pkl
                                                                  │
   Live packets (scapy sniff)                                     │
   or .pcap upload (rdpcap)                                       │
            │                                                     │
            ▼                                                     ▼
   ┌──────────────────────┐        ┌──────────────────────────────────────┐
   │  features.py         │        │  RF  ·  DT  ·  Isolation Forest      │
   │  packets_to_df()     │───────►│  (+ anomaly.py verdict mapping)      │
   │  2s/100-conn window  │        └──────────────┬───────────────────────┘
   └──────────────────────┘                       │
                                                  ▼
            ┌─────────────────────────────────────────────────────────┐
            │                app.py  (Streamlit UI)                    │
            │  Live Capture · Upload · Explainable AI · History        │
            └──┬───────────┬────────────┬───────────┬─────────────────┘
               ▼           ▼            ▼           ▼
         storage.py    alerts.py    geo.py    reporting.py
         (SQLite)      (5 channels) (GeoIP)   (PDF)
               │           │
               ▼           ▼
          api.py      notify.py · firewall.py · auth.py · crypto.py
        (REST/JSON)   (sound)     (blocks)     (login)   (backup)
```

Full breakdown in [docs/architecture/architecture.md](docs/architecture/architecture.md).

---

## 🛠️ Technology Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11+ |
| UI Framework | Streamlit |
| Charts | Altair (Vega-Lite) |
| Packet Capture | scapy (Npcap on Windows, raw sockets on Linux/macOS) |
| Machine Learning | scikit-learn — RandomForest, DecisionTree, IsolationForest |
| Dataset | NSL-KDD (41 features) |
| Persistence | SQLite (stdlib `sqlite3`) |
| Reporting | reportlab (PDF) · openpyxl (Excel) |
| Crypto | `cryptography` (Fernet) · PBKDF2-SHA256 via `hashlib` |
| GeoIP | `geoip2` + MaxMind GeoLite2 (optional) |
| REST API | stdlib `http.server` — no framework |
| Desktop build | PyInstaller (folder build + launcher) |
| Tests | pytest (84) · ruff |

### Dependencies

| Package | Purpose |
|---------|---------|
| `streamlit`, `altair` | Dashboard and charts |
| `scikit-learn`, `joblib`, `pandas`, `numpy` | Models and data handling |
| `scapy` | Live capture and pcap parsing |
| `reportlab`, `openpyxl` | PDF and Excel export |
| `cryptography` | Encrypted history backup |
| `geoip2` | Optional GeoIP world map |

---

## 🚀 Getting Started

### Requirements
- Python 3.11 or higher
- **Windows only:** [Npcap](https://npcap.com/#download) for live capture (pcap upload works without it)
- Live capture needs Administrator (Windows) or root / `CAP_NET_RAW` (Linux/macOS)

### Quick launch (desktop app)
Double-click **`NIDS.exe`** from a built `dist/NIDS/` folder — no Python required.
Build it with `python scripts/build_exe.py`, or see [docs/deployment/desktop-exe.md](docs/deployment/desktop-exe.md).

### Clone and run from source

```bash
git clone https://github.com/SufiyanAasim/network-analysis-intrusion-system.git
cd network-analysis-intrusion-system
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

```bash
streamlit run src/nids/app.py
```

Open the URL Streamlit prints (default `http://localhost:8501`).

### Other entry points

```bash
python scripts/train_models.py    # retrain all three models
python -m nids.api                # REST API on 127.0.0.1:8600
python scripts/build_exe.py       # build dist/NIDS/NIDS.exe
make test && make lint            # pytest + ruff
```

Full setup details in [docs/guides/running-locally.md](docs/guides/running-locally.md).

---

## ⚙️ Configuration

All settings are optional — the app runs with none of them. Copy `.env.example` to `.env` and adjust.

| Variable | Default | Description |
|----------|---------|-------------|
| `CRITICAL_THRESHOLD_PCT` | `20` | % of traffic flagged before status escalates to CRITICAL |
| `ALERT_COOLDOWN_SECONDS` | `60` | Minimum seconds between two alerts for the same model |
| `NIDS_DB_PATH` | `data/history.db` | Detection-history database location |
| `SLACK_WEBHOOK_URL` | — | Slack incoming-webhook URL |
| `ALERT_WEBHOOK_URL` | — | Generic JSON webhook |
| `ALERT_SMTP_HOST` / `ALERT_EMAIL_TO` | — | Email alerting (see `.env.example`) |
| `PAGERDUTY_ROUTING_KEY` | — | PagerDuty Events API v2 key |
| `TEAMS_WEBHOOK_URL` | — | Microsoft Teams incoming webhook |
| `NIDS_AUTH_PASSWORD_HASH` | — | Enables the login gate (`python -m nids.auth` to generate) |
| `NIDS_AUTH_USERS` | — | JSON list of users with `admin`/`viewer` roles |
| `NIDS_API_TOKEN` | — | Bearer token for the REST API |
| `NIDS_DB_ENCRYPTION_KEY` | — | Fernet key enabling the encrypted backup |
| `GEOIP_DB_PATH` | — | MaxMind GeoLite2-City `.mmdb` for the world map |

---

## 🗂️ Project Structure

```
network-analysis-intrusion-system/
├── .github/                # Issue/PR templates, CI (lint · test · retrain)
├── assets/images/          # Logo and dataset preview images
├── config/                 # Feature schema reference
├── data/
│   ├── nsl-kdd/            # NSL-KDD train/test sets
│   ├── pcaps/              # Sample captures for manual testing
│   └── history.db          # Detection history (runtime, gitignored)
├── docs/
│   ├── api/                # REST API reference
│   ├── architecture/       # System architecture
│   ├── deployment/         # Desktop .exe build guide
│   ├── guides/             # User and local-run guides
│   ├── releases/           # Per-version release notes (v1–v8)
│   └── troubleshooting/    # Common issues and fixes
├── models/                 # Trained rf/dt/iforest .pkl models
├── notebooks/              # Original coursework artefacts (historical — not live code)
│   ├── TheCode.ipynb           # The original notebook, as written
│   └── TheCode.py              # Same notebook flattened to a script
├── scripts/
│   ├── train_models.py         # CLI retraining
│   ├── desktop_launcher.py     # Frozen .exe entry point
│   └── build_exe.py            # PyInstaller build wrapper
├── src/nids/               # Application package  (○ @SufiyanAasim · ● @13eeCoder)
│   ├── app.py                  # ○ Streamlit UI · tabs · sidebar · charts
│   ├── features.py             # ● Packets → 41 NSL-KDD features (2s/100-conn window)
│   ├── netcheck.py             # ● Capture readiness · Npcap/libpcap detection
│   ├── throughput.py           # ● Per-second packets/sec · KB/sec aggregation
│   ├── geo.py                  # ● IP classification (RFC1918/public) + GeoIP
│   ├── auth.py                 # ● PBKDF2-SHA256 login + admin/viewer roles
│   ├── crypto.py               # ● Fernet-encrypted history backup
│   ├── firewall.py             # ● iptables/ufw/nftables/netsh block suggestions
│   ├── alerts.py               # ● Slack · webhook · email · PagerDuty · Teams
│   ├── notify.py               # ● Beep synthesis + browser notification
│   ├── anomaly.py              # ○ Isolation Forest verdict mapping
│   ├── storage.py              # ○ SQLite persistence and queries
│   ├── reporting.py            # ○ PDF report generation
│   └── api.py                  # ○ Read-only REST API
├── tests/                  # pytest suite (84 tests)
├── nids.spec               # PyInstaller spec
├── Dockerfile              # Container image
├── docker-compose.yml
├── Makefile                # install · run · api · test · lint · train
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── RELEASE.md
├── ROADMAP.md
├── SECURITY.md
└── SUPPORT.md
```

---

## 🧪 Testing

```bash
pytest -q                          # 84 tests
ruff check src tests scripts       # lint
```

Every module is deliberately **free of Streamlit imports** so its logic is unit-testable without a Streamlit runtime — `app.py` holds the UI, everything else is pure logic.

Areas not covered by automated tests (validated manually):
1. Live capture against real traffic (needs Npcap + Administrator).
2. The packaged `.exe` — launch it and confirm the dashboard serves and the History tab resolves its database path.
3. Real alert delivery to Slack/PagerDuty/Teams (the HTTP calls are mocked in tests).

---

## 🛡️ Security

The dashboard is **open by default** — enable the login gate before exposing it beyond localhost. Passwords are only ever stored as PBKDF2-SHA256 hashes (260k iterations, per-hash salt, constant-time compare); plaintext is never written to disk or logs.

Block suggestions are **display-only** — the app never executes a firewall command or changes system state. The REST API is read-only and ships no write endpoints. Model files are loaded with `joblib`, which can execute arbitrary code — only load `.pkl` files you trust.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

---

## 🤝 Contributors

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/SufiyanAasim">
        <img src="https://github.com/SufiyanAasim.png" width="72" alt="SufiyanAasim"/><br/>
        <sub><b>Mohammad Sufiyan Aasim</b></sub>
      </a><br/>
      <sub>Data Science · AI/ML · MLOps · SQE</sub>
    </td>
    <td align="center">
      <a href="https://github.com/13eeCoder">
        <img src="https://github.com/13eeCoder.png" width="72" alt="13eeCoder"/><br/>
        <sub><b>Muhammad Taha Siddiqui</b></sub>
      </a><br/>
      <sub>Networking · Cybersecurity</sub>
    </td>
  </tr>
</table>

### Who owns what

The codebase is split along each maintainer's domain — see
[.github/CODEOWNERS](.github/CODEOWNERS) for the authoritative per-file map.

| Domain | Modules | Owner |
| --- | --- | --- |
| **Traffic capture & analysis** | `features.py` · `netcheck.py` · `throughput.py` · `geo.py` · `data/pcaps/` | [@13eeCoder](https://github.com/13eeCoder) |
| **Security controls & response** | `auth.py` · `crypto.py` · `firewall.py` · `alerts.py` · `notify.py` · `SECURITY.md` | [@13eeCoder](https://github.com/13eeCoder) |
| **Models & data science** | `anomaly.py` · `scripts/train_models.py` · `models/` · `notebooks/` · `data/nsl-kdd/` | [@SufiyanAasim](https://github.com/SufiyanAasim) |
| **Dashboard, storage & API** | `app.py` · `storage.py` · `reporting.py` · `api.py` | [@SufiyanAasim](https://github.com/SufiyanAasim) |
| **MLOps, build & quality** | `.github/workflows/` · `nids.spec` · `scripts/build_exe.py` · `Dockerfile` · `tests/` | [@SufiyanAasim](https://github.com/SufiyanAasim) |

See [CONTRIBUTING.md](CONTRIBUTING.md) to get involved.

---

## 📄 License

[MIT License](LICENSE) © 2026 Network Analysis Intrusion System Contributors.

Trained on the [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) dataset from the Canadian Institute for Cybersecurity — see [docs/DATASET.md](docs/DATASET.md) for citation and terms.

---

<div align="center">

⭐ **Star this repo if you like watching three models argue about your traffic.**

[Report Bug](.github/ISSUE_TEMPLATE/bug_report.md) · [Request Feature](.github/ISSUE_TEMPLATE/feature_request.md) · [Changelog](CHANGELOG.md)

</div>
