# Dataset

This project trains and evaluates its models on **NSL-KDD**, a refined
version of the KDD Cup 1999 network intrusion dataset.

## What it is

NSL-KDD was created by Tavallaee, Bagheri, Lu, and Ghorbani (University of
New Brunswick) to fix well-documented problems in the original 1999 KDD Cup
dataset — most notably a huge number of duplicate/redundant records, which
biased classifiers toward frequent record types and made published accuracy
numbers on the original set misleading. NSL-KDD removes those duplicates and
rebalances difficulty across records, making it a more reliable benchmark
for intrusion-detection research even though the underlying traffic capture
is the same 1998 DARPA-derived data.

- Paper: M. Tavallaee, E. Bagheri, W. Lu, A. A. Ghorbani, *"A Detailed
  Analysis of the KDD CUP 99 Data Set,"* IEEE Symposium on Computational
  Intelligence for Security and Defense Applications (CISDA), 2009.
- Distributor: Canadian Institute for Cybersecurity (CIC), University of
  New Brunswick — <https://www.unb.ca/cic/datasets/nsl.html>

## Files used in this repo

Located in [`data/nsl-kdd/`](../data/nsl-kdd/):

| File | Purpose |
| --- | --- |
| `KDDTrain+.txt` / `.arff` | Full training set — used to fit the models and fit the categorical label encoders. |
| `KDDTrain+_20Percent.txt` / `.arff` | A 20% stratified subset of the training set, for faster iteration. |
| `KDDTest+.txt` / `.arff` | Full test set — used to report the sidebar accuracy figures. |
| `KDDTest-21.txt` / `.arff` | A harder test subset excluding records every submitted classifier in the original KDD Cup got 100% correct on. |

`.txt` files are plain comma-separated records (no header); `.arff` is the
same data in Weka's ARFF format. This project only reads the `.txt` files
(see `COLUMNS` in `scripts/train_models.py` and `src/nids/app.py`).

## Record format

Each record has the 41 features listed in [`config/features.yaml`](../config/features.yaml),
plus two trailing columns not used as model input:

- `label` — `normal` or one of ~39 specific attack names, grouped into four
  attack categories: **DoS** (denial of service), **Probe** (surveillance/
  scanning), **R2L** (remote-to-local, e.g. guessing a password), and
  **U2R** (user-to-root, privilege escalation).
- `difficulty_level` — how many of 21 learners in the original KDD Cup
  correctly classified that record (lower = harder).

This project's models treat it as **binary** classification: `label ==
'normal'` → `0`, anything else → `1` (`ATTACK`). See
`preprocess_data`/training code in `src/nids/features.py` and
`scripts/train_models.py`.

## Live/uploaded traffic vs. the dataset

Live-captured or uploaded `.pcap` traffic is mapped into the *same* 41-column
shape (`src/nids/features.py::packets_to_df`) so it can be fed to models
trained on NSL-KDD — but it's an approximation of real connection records
computed from raw packets, not NSL-KDD data itself. See the "Known
simplification" note in [docs/architecture/architecture.md](architecture/architecture.md).

## License / usage

NSL-KDD is distributed by CIC/UNB for research use; see the dataset page
above for their current terms before any redistribution or commercial use.
This repo includes the dataset files for convenience of running the project
end-to-end — they are not original work of this project.
