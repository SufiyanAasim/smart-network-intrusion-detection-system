"""Consensus threat triage across the available detection models.

The supervised and anomaly models intentionally remain independent.  This
module adds an operator-facing consensus layer without changing their raw
predictions: each available model contributes one vote and the vote ratio is
converted into a deterministic risk score and triage level.
"""

ATTACK_VERDICT = "Attack"
NORMAL_VERDICT = "Normal"

TRIAGE_CLEAR = "Clear"
TRIAGE_GUARDED = "Guarded"
TRIAGE_ELEVATED = "Elevated"
TRIAGE_CRITICAL = "Critical"

MODEL_VERDICT_COLUMNS = ("RF Analysis", "DT Analysis", "Anomaly Analysis")


def severity_for_score(score):
    """Map an integer 0-100 risk score to an operator-friendly severity."""
    score = max(0, min(100, int(score)))
    if score == 0:
        return TRIAGE_CLEAR
    if score < 50:
        return TRIAGE_GUARDED
    if score < 75:
        return TRIAGE_ELEVATED
    return TRIAGE_CRITICAL


def score_verdicts(verdicts):
    """Return ``(attack_votes, model_votes, risk_score, severity)``.

    Missing verdicts are ignored, which keeps the feature useful when the
    optional Isolation Forest artifact has not been installed.
    """
    available = [value for value in verdicts if value is not None]
    if not available:
        return 0, 0, 0, TRIAGE_CLEAR
    # Accept legacy decorated labels while new detections use clean text. This
    # keeps triage stable for existing databases during the v10 migration.
    attacks = sum(
        isinstance(value, str) and "attack" in value.casefold()
        for value in available
    )
    score = round(attacks / len(available) * 100)
    return attacks, len(available), score, severity_for_score(score)


def add_triage_columns(df):
    """Return a copy with Attack Votes, Risk Score, and Triage columns."""
    result = df.copy()
    verdict_columns = [name for name in MODEL_VERDICT_COLUMNS if name in result.columns]
    if not verdict_columns:
        result["Attack Votes"] = 0
        result["Risk Score"] = 0
        result["Triage"] = TRIAGE_CLEAR
        return result

    scored = result[verdict_columns].apply(
        lambda row: score_verdicts(row.tolist()), axis=1, result_type="expand"
    )
    scored.columns = ["Attack Votes", "Model Votes", "Risk Score", "Triage"]
    result[["Attack Votes", "Model Votes", "Risk Score", "Triage"]] = scored
    return result
