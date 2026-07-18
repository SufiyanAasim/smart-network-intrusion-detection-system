import pandas as pd
import pytest

from nids import reporting


def _classified_df():
    return pd.DataFrame(
        [
            {"src_ip": "10.0.0.1", "RF Analysis": "Attack", "DT Analysis": "Attack", "Triage": "Critical", "Risk Score": 100},
            {"src_ip": "10.0.0.1", "RF Analysis": "Attack", "DT Analysis": "Normal", "Triage": "Elevated", "Risk Score": 50},
            {"src_ip": "10.0.0.2", "RF Analysis": "Normal", "DT Analysis": "Normal", "Triage": "Clear", "Risk Score": 0},
        ]
    )


def test_attack_counts_and_top_ips():
    df = _classified_df()
    assert reporting._attack_counts(df, "RF Analysis") == 2
    assert reporting._attack_counts(df, "DT Analysis") == 1
    top = reporting._top_ips(df, "RF Analysis")
    assert top[0] == ("10.0.0.1", 2)


def test_build_report_pdf_returns_pdf_bytes():
    pytest.importorskip("reportlab")
    pdf = reporting.build_report_pdf(_classified_df(), generated_at="2026-07-17T00:00:00")
    assert pdf is not None
    assert pdf[:4] == b"%PDF"


def test_top_ips_empty_when_no_attacks():
    df = pd.DataFrame([{"src_ip": "10.0.0.2", "RF Analysis": "Normal"}])
    assert reporting._top_ips(df, "RF Analysis") == []


def test_browser_print_script_targets_parent_dashboard():
    script = reporting.browser_print_script("unique-print")
    assert "window.parent.print()" in script
    assert "unique-print" in script
    assert script.startswith("<script>")
