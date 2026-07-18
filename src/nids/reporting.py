"""PDF report generation for a classified detection batch.

Uses reportlab (pure Python, no system libraries). reportlab is imported
lazily so the rest of the app still works if it isn't installed — callers
should treat a None return as "PDF export unavailable" and fall back to CSV.

Kept free of Streamlit imports so it can be unit tested directly.
"""

import io
from datetime import datetime, timezone


def _attack_counts(df, verdict_col):
    if verdict_col not in df.columns:
        return 0
    return int(df[verdict_col].astype(str).str.contains("ATTACK").sum())


def _top_ips(df, verdict_col, ip_col="src_ip", limit=5):
    """Return [(ip, attack_count), ...] for the IPs flagged most by a model."""
    if verdict_col not in df.columns or ip_col not in df.columns:
        return []
    attacks = df[df[verdict_col].astype(str).str.contains("ATTACK")]
    if attacks.empty:
        return []
    return list(attacks[ip_col].value_counts().head(limit).items())


def build_report_pdf(df_display, title="NIDS Detection Report", generated_at=None):
    """Render a one-page PDF summary of a classified batch to bytes.

    `df_display` is expected to have the RF/DT verdict columns produced by
    the app's classify(). Returns PDF bytes, or None if reportlab isn't
    installed. `generated_at` (ISO string) is injected rather than read from
    the clock so callers can control/stamp it.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.pdfgen import canvas
    except ImportError:
        return None

    if generated_at is None:
        generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    total = len(df_display)
    rf_attacks = _attack_counts(df_display, "RF Analysis")
    dt_attacks = _attack_counts(df_display, "DT Analysis")
    anomaly_attacks = _attack_counts(df_display, "Anomaly Analysis")

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 2 * cm

    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(2 * cm, y, title)
    y -= 0.8 * cm

    pdf.setFont("Helvetica", 10)
    pdf.setFillColor(colors.grey)
    pdf.drawString(2 * cm, y, f"Generated: {generated_at} (UTC)")
    pdf.setFillColor(colors.black)
    y -= 1.2 * cm

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(2 * cm, y, "Summary")
    y -= 0.7 * cm
    pdf.setFont("Helvetica", 11)
    for label, value in (
        ("Total records analyzed", total),
        ("Random Forest attacks flagged", rf_attacks),
        ("Decision Tree attacks flagged", dt_attacks),
        ("Isolation Forest anomalies flagged", anomaly_attacks),
    ):
        pdf.drawString(2.4 * cm, y, f"- {label}: {value}")
        y -= 0.6 * cm

    y -= 0.4 * cm
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(2 * cm, y, "Top suspected attackers (Random Forest)")
    y -= 0.7 * cm
    pdf.setFont("Helvetica", 11)
    top = _top_ips(df_display, "RF Analysis")
    if top:
        for ip, count in top:
            pdf.drawString(2.4 * cm, y, f"- {ip}: {count} attack rows")
            y -= 0.6 * cm
    else:
        pdf.drawString(2.4 * cm, y, "- None flagged.")
        y -= 0.6 * cm

    pdf.showPage()
    pdf.save()
    return buffer.getvalue()
