# Troubleshooting

## "Could not find 'KDDTrain+.txt'" on startup

`app.py` looks for the training set at `data/nsl-kdd/KDDTrain+.txt` relative
to the repo root. Make sure you're running `streamlit run` from the repo
root, and that `data/nsl-kdd/` wasn't moved or excluded.

## `ModuleNotFoundError: No module named 'nids'`

Happens if `src/nids/app.py` is copied/run outside the repo. `app.py`
inserts `src/` onto `sys.path` at startup, so keep `src/nids/app.py` and
`src/nids/features.py` in the same relative layout.

## Live capture doesn't return any packets

- You likely lack raw-socket privileges — see [running-locally.md](../guides/running-locally.md#notes).
- On Windows, `scapy` needs [Npcap](https://npcap.com/) installed.
- Corporate VPNs/firewalls can block raw capture even when running as admin.

## Live capture accuracy looks worse than the sidebar number

Expected — see the "Known simplification" note in
[docs/architecture/architecture.md](../architecture/architecture.md).
The sidebar accuracy is measured on the NSL-KDD test set, not live traffic.

## `joblib.load` errors after pulling new code

The `.pkl` files are tied to the scikit-learn version they were trained
with. If you upgrade `scikit-learn`, retrain with
`python scripts/train_models.py`.

## No "🧭 Isolation Forest" column / sidebar says the model isn't found

`models/iforest_model.pkl` is included from v3.0.0 (Watchtower) onward. If
you're on an older checkout or deleted it, regenerate it with
`python scripts/train_models.py` — the app works fine with just RF/DT until then.

## Alerts aren't firing on a critical threat

- Check `.env` has at least one of `SLACK_WEBHOOK_URL`, `ALERT_WEBHOOK_URL`,
  or `ALERT_SMTP_HOST`/`ALERT_EMAIL_FROM`/`ALERT_EMAIL_TO` set — all
  channels are opt-in and silently skipped if unconfigured.
- Alerts are cooldown-throttled per model (`ALERT_COOLDOWN_SECONDS`,
  default 60s) — a second CRITICAL reading within the cooldown window won't
  re-alert.
- A failed channel never raises; check the "🔔 Alert sent via: ..." caption
  under the summary to see which channels actually succeeded.

## The desktop `NIDS.exe` opens a console but no dashboard

Give it a few seconds on first launch — a ~350 MB bundle has to load
scikit-learn and the models. The console prints the local URL once ready. If
it exits immediately, run it from a terminal to see the error.

## `NIDS.exe`: where did my detection history go?

Not next to the .exe. The bundle is unpacked to a temp dir that Windows wipes
on exit, so history is written to `%LOCALAPPDATA%\NIDS\history.db`
(`~/.local/share/NIDS/` on Linux, `~/Library/Application Support/NIDS/` on
macOS). Set `NIDS_DB_PATH` to put it elsewhere.

## `data/history.db` growing large / locked errors under heavy live capture

SQLite handles the write volume from a single-user dashboard fine, but if
you see `database is locked` errors under unusually heavy concurrent load,
close other processes reading `data/history.db` at the same time (e.g. a
DB browser tool) — SQLite allows only one writer at a time.
