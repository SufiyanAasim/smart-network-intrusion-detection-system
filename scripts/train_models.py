"""Retrain the Random Forest, Decision Tree, and Isolation Forest models from
data/nsl-kdd/.

This mirrors the training steps in notebooks/TheCode.ipynb so models can be
regenerated from the CLI instead of re-running the notebook. Run from repo
root: `python scripts/train_models.py`.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC_DIR = os.path.join(BASE_DIR, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

import joblib  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.ensemble import IsolationForest, RandomForestClassifier  # noqa: E402
from sklearn.preprocessing import LabelEncoder  # noqa: E402
from sklearn.tree import DecisionTreeClassifier  # noqa: E402

from nids.features import MODEL_FEATURES, preprocess_data  # noqa: E402

DATA_DIR = os.path.join(BASE_DIR, "data", "nsl-kdd")
MODELS_DIR = os.path.join(BASE_DIR, "models")

COLUMNS = MODEL_FEATURES + ["label", "difficulty_level"]
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]


def main():
    train_df = pd.read_csv(os.path.join(DATA_DIR, "KDDTrain+.txt"), names=COLUMNS)

    encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        le.fit(train_df[col])
        encoders[col] = le

    X_train = preprocess_data(train_df[MODEL_FEATURES], encoders)
    y_train = train_df["label"].apply(lambda x: 0 if x == "normal" else 1)

    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train)

    dt_model = DecisionTreeClassifier(random_state=42)
    dt_model.fit(X_train, y_train)

    # Isolation Forest is unsupervised: fit only on normal traffic so it
    # learns what "normal" looks like and flags deviations as anomalies,
    # rather than learning attack signatures like RF/DT do.
    iforest_model = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
    iforest_model.fit(X_train[y_train == 0])

    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(rf_model, os.path.join(MODELS_DIR, "rf_model.pkl"))
    joblib.dump(dt_model, os.path.join(MODELS_DIR, "dt_model.pkl"))
    joblib.dump(iforest_model, os.path.join(MODELS_DIR, "iforest_model.pkl"))
    print(f"Saved models to {MODELS_DIR}")


if __name__ == "__main__":
    main()
