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
