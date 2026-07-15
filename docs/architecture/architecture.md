# Architecture

## Overview

The system has two independent data paths that both feed the same
classification + display pipeline:

1. **Training path** (offline): `data/nsl-kdd/KDDTrain+.txt` →
   `scripts/train_models.py` → `models/rf_model.pkl`, `models/dt_model.pkl`.
2. **Inference path** (runtime, in `src/nids/app.py`):
   - Live packets (scapy `sniff`) or an uploaded `.pcap` (scapy `rdpcap`)
   - → `src/nids/features.py::packets_to_df` (maps raw packets to the
     41 NSL-KDD feature columns)
   - → `preprocess_data` (label-encodes `protocol_type`, `service`, `flag`
     using encoders fit on the training set)
   - → `rf_model.predict` / `dt_model.predict`
   - → Streamlit tables + Altair charts + rule-based summary.

## Why feature engineering is a separate module

`src/nids/features.py` has no Streamlit dependency, so it can be:
- Unit tested directly (`tests/test_features.py`), and
- Reused by `scripts/train_models.py` so training and inference always
  agree on the feature schema.

## Known simplification (tracked in ROADMAP.md)

Several NSL-KDD statistical fields (`same_srv_rate`, `dst_host_*_rate`, etc.)
are approximated from a single packet or a small live window rather than
computed over the full 2-second/100-connection windows the original NSL-KDD
feature definitions use. This keeps live capture fast but means accuracy on
live traffic will be lower than the reported test-set accuracy shown in the
sidebar (which is measured on the real NSL-KDD test set).

## Model I/O contract

- Input: DataFrame with exactly `MODEL_FEATURES` (see `config/features.yaml`), in order.
- Output: `0` (normal) or `1` (attack) per row.
