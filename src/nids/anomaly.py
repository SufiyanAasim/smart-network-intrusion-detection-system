"""Helpers for the unsupervised Isolation Forest anomaly-detection model.

IsolationForest.predict returns 1 for inliers ("normal") and -1 for outliers
("anomaly"). These helpers translate that into the same verdict/label
conventions the supervised RF/DT models use elsewhere in the app.
"""

def to_verdict(predictions):
    """Map IsolationForest predictions to the UI's ATTACK/Normal labels."""
    return ['🚨 ATTACK' if p == -1 else '✅ Normal' for p in predictions]


def to_binary(predictions):
    """Map IsolationForest predictions to 0 (normal) / 1 (attack), matching
    the RF/DT label convention used for accuracy scoring."""
    return [1 if p == -1 else 0 for p in predictions]
