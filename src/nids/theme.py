"""Shared design tokens and Altair chart theme for the Streamlit UI.

Pure/stdlib-only (plus Altair) so it carries no Streamlit dependency and can
be imported by scripts or tests without a running app. `app.py` is the single
consumer today; new charts/screens should read spacing, color, and chart
sizing from here instead of hardcoding values inline.
"""

import altair as alt

SPACING = {
    "xs": "4px",
    "sm": "8px",
    "md": "12px",
    "lg": "16px",
    "xl": "24px",
    "xxl": "32px",
}

TYPE_SCALE = {
    "caption": "0.76rem",
    "body": "0.86rem",
    "label": "0.9rem",
    "subheading": "1.05rem",
    "heading": "1.3rem",
    "hero": "clamp(1.7rem,2.45vw,2.45rem)",
}

# One palette for the whole app, so a model/verdict reads as the same colour
# in the sidebar, its results column, and every chart.
COLOR = {
    "normal": "#00CC96",
    "attack": "#EF553B",
    "rf": "#00CC96",
    "dt": "#FFB84C",
    "iforest": "#22D3EE",
    "border": "rgba(128,128,128,.22)",
    "border-strong": "rgba(128,128,128,.35)",
    "surface": "rgba(128,128,128,.07)",
    "footer-divider": "rgba(128,128,128,.15)",
}

CARD = {
    "radius": "12px",
    "min_height": "240px",
    "padding": "0.45rem 0.7rem",
}

# Chart-sizing tokens so height/row-unit magic numbers live in one place.
CHART_HEIGHT = {
    "card_chart": 240,
    "donut": 220,
    "bar_row_unit": 26,
    "min_bar_chart": 140,
}


def dynamic_height(n_rows, unit=CHART_HEIGHT["bar_row_unit"], minimum=CHART_HEIGHT["min_bar_chart"]):
    """Chart height that grows with category count instead of clipping labels.

    A fixed short height on a horizontal bar chart is what causes IP/label
    rows to overlap once there are more than a handful of categories.
    """
    return max(minimum, unit * max(n_rows, 1))


def nids_chart_theme():
    """Altair theme config applied to every chart via alt.themes.enable("nids").

    Consolidates axis/legend/title styling so charts stop looking different
    from each other (tick color, gridlines, label size, title weight).
    """
    return {
        "config": {
            "axis": {
                "labelFontSize": 11,
                "titleFontSize": 12,
                "titleFontWeight": 600,
                "gridColor": "rgba(128,128,128,.15)",
                "domainColor": "rgba(128,128,128,.3)",
                "tickColor": "rgba(128,128,128,.3)",
                "titleAngle": 0,
                "titleAlign": "left",
            },
            "legend": {
                "labelFontSize": 11,
                "titleFontSize": 11,
                "symbolSize": 60,
            },
            "title": {
                "fontSize": 13,
                "fontWeight": 700,
                "anchor": "start",
            },
            "view": {"stroke": None},
        }
    }


def register():
    """Register and enable the shared theme. Call once at module load."""
    alt.themes.register("nids", nids_chart_theme)
    alt.themes.enable("nids")
