import pandas as pd

from nids import triage


def test_score_verdicts_uses_available_models_only():
    assert triage.score_verdicts(["Attack", "Normal", None]) == (
        1, 2, 50, triage.TRIAGE_ELEVATED
    )


def test_three_model_consensus_levels():
    assert triage.score_verdicts(["Normal"] * 3)[3] == triage.TRIAGE_CLEAR
    assert triage.score_verdicts(["Attack", "Normal", "Normal"])[3] == (
        triage.TRIAGE_GUARDED
    )
    assert triage.score_verdicts(["Attack", "Attack", "Normal"])[3] == (
        triage.TRIAGE_ELEVATED
    )
    assert triage.score_verdicts(["Attack"] * 3)[3] == triage.TRIAGE_CRITICAL


def test_add_triage_columns_does_not_mutate_input():
    source = pd.DataFrame(
        [{"RF Analysis": "Attack", "DT Analysis": "Attack"}]
    )
    result = triage.add_triage_columns(source)

    assert "Triage" not in source.columns
    assert result.iloc[0]["Attack Votes"] == 2
    assert result.iloc[0]["Model Votes"] == 2
    assert result.iloc[0]["Risk Score"] == 100
    assert result.iloc[0]["Triage"] == triage.TRIAGE_CRITICAL
