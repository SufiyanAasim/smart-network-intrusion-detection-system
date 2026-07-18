import base64
import hashlib
import html
import io
import os
import sys
import traceback

# Make the `nids` package importable when this file is launched directly via
# `streamlit run src/nids/app.py` (Streamlit runs it as a standalone script,
# so `src/` needs to be on sys.path for `from nids.features import ...`).
_SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

_BASE_DIR = os.path.dirname(_SRC_DIR)
_LOGO_PATH = os.path.join(_BASE_DIR, "assets", "images", "logo.png")
_CONTRIBUTOR_IMAGE_DIR = os.path.join(_BASE_DIR, "assets", "images", "contributors")
PRODUCT_NAME = "Smart Network Intrusion Detection System"
RELEASE_CODENAME = "Cipher"

from dotenv import load_dotenv  # noqa: E402

# Local source runs do not inherit values from `.env` automatically. Load it
# before authentication and integration modules inspect the environment, while
# preserving any values explicitly supplied by Docker, Render, or the shell.
load_dotenv(os.path.join(_BASE_DIR, ".env"), override=False)

import streamlit as st  # noqa: E402
import streamlit.components.v1 as components  # noqa: E402
import pandas as pd  # noqa: E402
import joblib  # noqa: E402
from scapy.all import sniff, rdpcap  # noqa: E402
from scapy.error import Scapy_Exception  # noqa: E402
from sklearn.preprocessing import LabelEncoder  # noqa: E402
from sklearn.metrics import accuracy_score  # noqa: E402
import tempfile  # noqa: E402
import altair as alt  # noqa: E402
import time  # noqa: E402

from nids.features import MODEL_FEATURES, WINDOW_CONNECTIONS, preprocess_data, packets_to_df  # noqa: E402
from nids import storage, alerts, anomaly, geo, reporting, throughput, notify, netcheck, auth, firewall, crypto, triage, autonomy, theme  # noqa: E402
from nids import __version__ as NIDS_VERSION  # noqa: E402

# Registers the shared "nids" Altair theme (axis/legend/title styling) so
# every chart in the app inherits consistent styling. Must run at module
# load, before any alt.Chart(...) is built.
theme.register()

# Raw packets kept in session_state for live capture, so packets_to_df can
# compute a real trailing window instead of a single-packet snapshot.
RAW_PACKET_BUFFER = WINDOW_CONNECTIONS * 3

# Minimum seconds between two critical-threat alerts for the same model, so a
# sustained attack doesn't spam Slack/email/webhook on every Streamlit rerun.
def _env_int(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


def _env_float(name, default, minimum, maximum):
    try:
        value = float(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


ALERT_COOLDOWN_SECONDS = _env_int("ALERT_COOLDOWN_SECONDS", 60, 1, 86_400)

# Default CRITICAL threshold (% of traffic flagged as attack) before a
# sidebar slider lets the user adjust it per session. SUSPICIOUS is anything
# above 0% and below this.
DEFAULT_CRITICAL_THRESHOLD_PCT = _env_int("CRITICAL_THRESHOLD_PCT", 20, 5, 100)

# Live capture pulls this many packets per script run before rerunning, so the
# Stop button stays responsive (see the Live Capture tab for why).
LIVE_BATCH_SIZE = _env_int("LIVE_BATCH_SIZE", 5, 1, 100)
LIVE_SNIFF_TIMEOUT = _env_float("LIVE_SNIFF_TIMEOUT", 1.0, 0.1, 30.0)
LIVE_REFRESH_SECONDS = _env_float("LIVE_REFRESH_SECONDS", 2.5, 0.5, 10.0)
MAX_PCAP_UPLOAD_MB = _env_int("MAX_PCAP_UPLOAD_MB", 50, 1, 200)

# One palette for the whole app, so a model reads as the same colour in the
# sidebar, its results column, and the Explainable AI charts. Values live in
# nids.theme.COLOR so future charts/screens share the same source of truth.
COLOR_NORMAL = theme.COLOR["normal"]
COLOR_ATTACK = theme.COLOR["attack"]
COLOR_RF = theme.COLOR["rf"]
COLOR_DT = theme.COLOR["dt"]
COLOR_IFOREST = theme.COLOR["iforest"]
VERDICT_SCALE = alt.Scale(domain=[triage.NORMAL_VERDICT, triage.ATTACK_VERDICT], range=[COLOR_NORMAL, COLOR_ATTACK])

# --- 1. Page Configuration ---
st.set_page_config(
    page_title=f"{RELEASE_CODENAME} · {PRODUCT_NAME}",
    page_icon=_LOGO_PATH,
    layout="wide",
)
st.markdown(
    """
    <style>
    :root {--nids-control-height:40px;}
    .block-container {max-width:1500px;padding-top:3.25rem;padding-bottom:1.25rem;}
    div[data-testid="stMetric"] {background:rgba(128,128,128,.07);
      border:1px solid rgba(128,128,128,.22);box-sizing:border-box;
      border-radius:12px;padding:13px 15px;height:auto;min-height:96px;
      display:flex;flex-direction:column;justify-content:space-between;}
    div[data-testid="stMetric"] > div {height:auto!important;}
    div[data-baseweb="tab-list"] {gap:.35rem;
      border-bottom:1px solid rgba(128,128,128,.25);}
    button[data-baseweb="tab"] {border-radius:9px 9px 0 0;padding:.55rem .8rem;}
    [data-testid="stButton"] button,
    [data-testid="stDownloadButton"] button,
    [data-testid="stFormSubmitButton"] button {height:var(--nids-control-height)!important;
      min-height:var(--nids-control-height)!important;max-height:var(--nids-control-height)!important;
      display:flex!important;align-items:center!important;justify-content:center!important;
      white-space:nowrap!important;}
    [data-testid="stButton"] button p,
    [data-testid="stDownloadButton"] button p,
    [data-testid="stFormSubmitButton"] button p {white-space:nowrap!important;
      overflow:hidden!important;text-overflow:ellipsis!important;}
    div[data-testid="InputInstructions"] {display:none!important;}
    button[data-testid="stMainMenuButton"] {border:1px solid rgba(128,128,128,.35)!important;
      border-radius:9px!important;width:36px!important;height:36px!important;
      min-height:36px!important;max-height:36px!important;}
    button[data-testid="stMainMenuButton"] svg {display:none!important;}
    button[data-testid="stMainMenuButton"]::before {content:"";display:block;width:16px;height:2px;
      background:currentColor;box-shadow:0 -5px 0 currentColor,0 5px 0 currentColor;}
    [data-testid="stToolbar"] {gap:0.4rem!important;}
    /* Manual Rerun is already surfaced by Streamlit's file-change header.
       Keep Auto rerun available in the hamburger menu as an explicit
       development preference. */
    [data-testid="stMainMenuItem-rerun"] {display:none!important;}
    [data-testid="stMainMenuItem-print"],
    [data-testid="stMainMenuItem-recordScreen"],
    [data-testid="stMainMenuItem-recordScreencast"] {display:none!important;}
    body:has(.nids-auth-shell) [data-testid="stMainMenuItem-autoRerun"] {display:none!important;}
    [data-testid="stAppDeployButton"] {transform:translateX(-9.1rem);}
    [data-testid="stStatusWidget"] {transform:translateX(-9.5rem);height:36px!important;
      display:flex!important;align-items:center!important;}
    /* Authentication has no notification action competing for header space.
       Keep Deploy and the native running indicator in their normal toolbar
       flow beside the hamburger; authenticated screens retain the app layout. */
    body:has(.nids-auth-shell) [data-testid="stAppDeployButton"],
    body:has(.nids-auth-shell) [data-testid="stStatusWidget"] {transform:none!important;}
    /* During capture/reruns the native running-person status is useful, but
       its header Stop action duplicates the explicit Stop Capture control. */
    [data-testid="stStatusWidgetRunningIcon"] {display:flex!important;align-items:center!important;}
    [data-testid="stStatusWidget"] [data-testid="stBaseButton-header"] {display:none!important;}
    [data-testid="stAppDeployButton"] button {height:36px!important;min-height:36px!important;
      max-height:36px!important;display:flex!important;align-items:center!important;
      border:1px solid rgba(128,128,128,.35)!important;border-radius:9px!important;
      padding:0 .75rem!important;}
    [data-testid="stSidebar"] {width:300px!important;}
    [data-testid="stSidebar"] .block-container {padding:.65rem 1rem 1rem!important;}
    [data-testid="stSidebar"] .block-container > [data-testid="stVerticalBlock"] {
      min-height:calc(100vh - 2.65rem);}
    [data-testid="stSidebar"] [data-testid="stVerticalBlock"] {gap:.5rem!important;}
    [data-testid="stSidebar"] .block-container > [data-testid="stVerticalBlock"] {
      gap:0!important;}
    [data-testid="stSidebar"] hr {margin:.45rem 0!important;}
    [data-testid="stSidebar"] button {height:var(--nids-control-height)!important;
      min-height:var(--nids-control-height)!important;max-height:var(--nids-control-height)!important;}
    .nids-sidebar-brand {text-align:center;margin:0 0 1rem;}
    .nids-sidebar-brand img {width:72px;height:72px;object-fit:contain;}
    .nids-sidebar-brand strong {display:block;margin-top:-.05rem;font-size:.82rem;
      letter-spacing:.14em;text-transform:uppercase;opacity:.88;}
    .nids-sidebar-heading {font-size:.7rem;font-weight:750;letter-spacing:.1em;
      line-height:1.2;text-transform:uppercase;opacity:.68;margin:0 0 .75rem;}
    .nids-sidebar-heading-row {display:flex;align-items:center;justify-content:space-between;
      gap:.75rem;margin:0 0 .75rem;}
    .nids-sidebar-heading-row .nids-sidebar-heading {margin:0;}
    .nids-threshold-value {color:var(--primary-color,#0891b2);font-size:.8rem;font-weight:750;
      font-variant-numeric:tabular-nums;}
    .st-key-sidebar_models_section,
    .st-key-sidebar_threshold_section {margin-top:1.25rem!important;}
    .st-key-sidebar_access_section [data-testid="stVerticalBlock"] {gap:0!important;}
    .st-key-sidebar_models_section [data-testid="stVerticalBlock"] {gap:0!important;}
    .st-key-sidebar_threshold_section [data-testid="stVerticalBlock"] {gap:.25rem!important;}
    .st-key-sidebar_access_group {border:1px solid rgba(128,128,128,.28);
      border-radius:14px;padding:.25rem .38rem .38rem;
      background:rgba(128,128,128,.045);}
    .st-key-sidebar_access_group [data-testid="stVerticalBlock"] {gap:0!important;}
    .st-key-sidebar_access_group .nids-role-card {border:0;background:transparent;
      color:inherit;border-radius:9px;padding:.3rem .3rem .4rem;margin:0;
      min-height:54px;box-sizing:border-box;}
    .st-key-sidebar_access_group .nids-role-badge {height:32px;display:flex;
      align-items:center;justify-content:center;width:100%;box-sizing:border-box;
      border:1px solid #0e7490;border-radius:999px;color:var(--primary-color,#22d3ee);
      background:transparent;font-size:.68rem;font-weight:800;letter-spacing:.09em;
      line-height:1;text-transform:uppercase;opacity:1;}
    .st-key-sidebar_access_group .nids-role-session {display:block;margin:.38rem .25rem 0;
      font-size:.76rem;line-height:1.2;opacity:.68;}
    .st-key-sidebar_access_group [data-testid="stElementContainer"]:has(.nids-role-card) {
      min-height:54px!important;margin-bottom:.625rem!important;overflow:visible!important;}
    .st-key-sidebar_access_group button {background:rgba(128,128,128,.035);}
    .st-key-sidebar_logout {margin-top:auto!important;padding-top:1.85rem;
      border-top:1px solid rgba(128,128,128,.2);}
    .st-key-sidebar_logout button {border-color:rgba(239,85,59,.38)!important;}
    .nids-model-state {display:flex;align-items:center;gap:.38rem;margin:0 0 .625rem;
      font-size:.72rem;opacity:.7;}
    .nids-model-state::before {content:"";width:7px;height:7px;border-radius:50%;
      background:#00CC96;box-shadow:0 0 0 3px rgba(0,204,150,.12);}
    .nids-accuracy-list {display:grid;gap:.625rem;}
    .nids-accuracy-row {display:flex;align-items:center;justify-content:space-between;
      gap:.75rem;border:1px solid rgba(128,128,128,.22);border-radius:10px;
      background:rgba(128,128,128,.055);padding:.5rem .75rem;min-height:42px;
      box-sizing:border-box;}
    .nids-accuracy-row span {font-size:.82rem;opacity:.82;}
    .nids-accuracy-row strong {font-size:1rem;font-weight:650;font-variant-numeric:tabular-nums;}
    .st-key-sidebar_threshold_section [data-testid="stThumbValue"] {display:none!important;}
    .st-key-top_notifications {position:fixed;right:3.65rem;top:0.75rem;width:auto!important;
      z-index:999990;margin:0!important;}
    .st-key-top_notifications button {height:36px!important;min-height:36px!important;max-height:36px!important;
      border:1px solid rgba(128,128,128,.35)!important;border-radius:9px!important;font-weight:600;
      padding:0 .75rem!important;display:flex!important;align-items:center!important;line-height:1!important;}
    .nids-hero {border:1px solid rgba(128,128,128,.25);
      border-radius:16px;padding:10px 16px;
      background:linear-gradient(135deg,rgba(128,128,128,.075),rgba(34,211,238,.025));
      box-shadow:0 12px 35px rgba(0,0,0,.09);margin-bottom:.45rem;}
    .nids-hero-logo {width:92px;height:92px;object-fit:contain;
      flex:0 0 auto;margin-left:clamp(.2rem,.7vw,.65rem);}
    .nids-hero-content {min-width:0;flex:1;}
    .nids-kicker {font-size:.76rem;font-weight:700;letter-spacing:.16em;
      text-transform:uppercase;margin-bottom:.2rem;}
    .nids-hero h1 {font-size:clamp(1.7rem,2.45vw,2.45rem);line-height:1.12;}
    .nids-subtitle {opacity:.68;font-size:.92rem;font-style:italic;}
    .st-key-live_record_control {min-height:2.6rem;display:flex;align-items:center;
      justify-content:stretch;}
    .st-key-live_record_control > div {width:100%;}
    .st-key-live_record_control iframe {display:block;margin:0!important;
      height:42px!important;}
    .st-key-live_print_control {min-height:2.6rem;display:flex;align-items:center;}
    .st-key-live_print_control > div {width:100%;}
    .st-key-live_print_control button {height:40px!important;min-height:40px!important;}
    .st-key-live_throughput_panel {min-height:230px!important;}
    .st-key-live_throughput_panel > div > [data-testid="stVerticalBlock"] {
      min-height:230px!important;}
    .st-key-live_results_panel hr {margin:.25rem 0 1rem!important;}
    .st-key-dashboard_export_control {min-height:2.6rem;display:flex;align-items:center;}
    .st-key-dashboard_export_control > div {width:100%;}
    .st-key-dashboard_export_control button {height:40px!important;min-height:40px!important;
      border:1px solid #0e7490!important;border-radius:8px!important;
      background:#0e7490!important;color:#fff!important;font-weight:600!important;}
    .st-key-dashboard_export_control button:hover {border-color:#155e75!important;
      background:#155e75!important;color:#fff!important;}
    .st-key-dashboard_chart_grid > div > [data-testid="stVerticalBlock"] {gap:1rem!important;}
    .st-key-dashboard_chart_grid [data-testid="stHorizontalBlock"] {gap:1rem!important;
      align-items:stretch!important;}
    /* align-items:stretch equalizes the stColumn height, but stLayoutWrapper
       (the column's inner content wrapper) defaults to flex-grow:0 and stays
       at its own content height, leaving a gap instead of the card itself
       filling the taller column. Force it to grow so the bordered card fills
       the stretched row height, not just the invisible column around it. */
    .st-key-dashboard_chart_grid [data-testid="stColumn"] {display:flex!important;}
    .st-key-dashboard_chart_grid [data-testid="stLayoutWrapper"] {flex:1 1 auto!important;
      display:flex!important;}
    .st-key-dashboard_chart_grid [data-testid="stLayoutWrapper"] > [data-testid="stVerticalBlock"] {
      flex:1 1 auto!important;}
    .st-key-dashboard_triage_card [data-testid="stVerticalBlockBorderWrapper"],
    .st-key-dashboard_model_card [data-testid="stVerticalBlockBorderWrapper"],
    .st-key-dashboard_risk_card [data-testid="stVerticalBlockBorderWrapper"],
    .st-key-dashboard_sources_card [data-testid="stVerticalBlockBorderWrapper"] {
      box-sizing:border-box;border:1px solid rgba(128,128,128,.22)!important;
      border-radius:12px!important;background:rgba(128,128,128,.07)!important;
      padding:.45rem .7rem!important;}
    .st-key-dashboard_triage_card [data-testid="stVerticalBlockBorderWrapper"],
    .st-key-dashboard_model_card [data-testid="stVerticalBlockBorderWrapper"],
    .st-key-dashboard_risk_card [data-testid="stVerticalBlockBorderWrapper"],
    .st-key-dashboard_sources_card [data-testid="stVerticalBlockBorderWrapper"] {
      min-height:240px;}
    .st-key-dashboard_triage_card [data-testid="stVerticalBlock"],
    .st-key-dashboard_model_card [data-testid="stVerticalBlock"],
    .st-key-dashboard_risk_card [data-testid="stVerticalBlock"],
    .st-key-dashboard_sources_card [data-testid="stVerticalBlock"] {gap:0!important;}
    [data-testid="stFileUploaderDropzone"] {min-height:56px!important;
      padding:.5rem .75rem!important;box-sizing:border-box!important;
      align-items:center!important;}
    [data-testid="stFileUploaderDropzone"] button {height:40px!important;
      min-height:40px!important;max-height:40px!important;display:flex!important;
      align-items:center!important;justify-content:center!important;}
    [data-testid="stFileUploaderDropzoneInstructions"] {align-self:center!important;}
    .nids-dialog-brand {display:grid;grid-template-columns:88px auto;align-items:center;
      column-gap:1.25rem;width:fit-content;
      margin:.45rem 0 1.25rem 0;}
    .nids-dialog-brand img {width:88px;height:88px;object-fit:contain;
      justify-self:center;}
    .nids-dialog-title {font-size:1.05rem;font-weight:750;line-height:1.25;}
    .nids-dialog-meta {opacity:.65;font-size:.86rem;margin-top:.35rem;}
    .nids-avatar {width:64px;height:64px;border-radius:50%;object-fit:cover;
      border:2px solid rgba(34,211,238,.7);padding:2px;
      background:rgba(128,128,128,.12);}
    .nids-credits-title {font-size:1.3rem;font-weight:800;line-height:1.2;
      margin:.4rem 0 .4rem;}
    .nids-contributors-grid {display:grid;grid-template-columns:repeat(2,minmax(0,1fr));
      gap:1rem;}
    .nids-contributor-card {border:1px solid rgba(128,128,128,.28);border-radius:12px;
      padding:.65rem .8rem;display:flex;flex-direction:column;min-height:194px;
      box-sizing:border-box;background:rgba(128,128,128,.025);}
    .nids-contributor-head {display:grid;grid-template-columns:64px minmax(0,1fr);
      align-items:center;gap:.75rem;}
    .nids-contributor-identity {display:flex;flex-direction:column;align-items:flex-start;
      gap:.28rem;padding:0;min-width:0;}
    .nids-contributor-name {font-size:1.05rem;font-weight:800;line-height:1.2;}
    .nids-contributor-domain {display:inline-flex;align-items:center;justify-content:center;
      border:1px solid rgba(34,211,238,.42);border-radius:999px;
      padding:.25rem .55rem;color:#22d3ee;background:rgba(34,211,238,.08);
      font-size:.66rem;font-weight:800;letter-spacing:.08em;white-space:nowrap;}
    .nids-contributor-identity a {font-size:.88rem;}
    .nids-contributor-responsibilities {font-size:.78rem;line-height:1.3;
      margin:.42rem 0 .5rem;flex:1;}
    .nids-contributor-responsibilities strong {display:block;margin-bottom:.18rem;}
    .nids-contributor-responsibilities ul {margin:0;padding-left:1.15rem;}
    .nids-contributor-responsibilities li {margin:.08rem 0;}
    .nids-github-action {height:34px;border:1px solid rgba(128,128,128,.38);
      border-radius:8px;display:flex;align-items:center;justify-content:center;
      color:inherit!important;text-decoration:none!important;font-size:.82rem;font-weight:700;}
    .nids-github-action:hover {border-color:#22d3ee;color:#0891b2!important;}
    .nids-credits-scope {margin:.42rem 0 .12rem;padding:.46rem .7rem;
      border-left:3px solid rgba(34,211,238,.7);background:rgba(128,128,128,.045);
      border-radius:0 8px 8px 0;font-size:.76rem;line-height:1.32;}
    .st-key-credits_footer_actions {margin-top:0!important;}
    .st-key-credits_footer_actions [data-testid="stVerticalBlock"] {gap:.25rem!important;}
    .nids-role-card {border:1px solid rgba(128,128,128,.28);border-radius:14px;
      padding:.85rem 1rem;margin:.1rem 0 .28rem;
      background:rgba(128,128,128,.07);}
    .nids-role-card strong {display:block;font-size:.92rem;}
    .nids-role-card span {opacity:.7;font-size:.78rem;}
    .nids-auth-shell {max-width:720px;margin:1.15rem auto .65rem;border:1px solid rgba(128,128,128,.24);
      border-radius:20px;padding:1.05rem 1.35rem .75rem;background:rgba(128,128,128,.06);
      box-shadow:0 24px 70px rgba(0,0,0,.14);text-align:center;}
    .nids-auth-logo {width:112px;height:112px;object-fit:contain;}
    .nids-auth-title {font-size:1.65rem;font-weight:800;margin:.15rem 0 .15rem;}
    .nids-auth-meta {opacity:.7;margin-bottom:.4rem;}
    .st-key-auth_primary_nav {margin-top:.75rem!important;}
    .st-key-auth_primary_nav [data-testid="stVerticalBlock"] {gap:0!important;}
    .nids-auth-role-help {text-align:center;opacity:.68;font-size:.8rem;margin:-.2rem 0 .65rem;}
    [data-testid="stMainBlockContainer"] > [data-testid="stVerticalBlock"] {
      min-height:calc(100vh - 4.5rem);}
    [data-testid="stElementContainer"]:has(.nids-footer) {margin-top:auto;}
    .nids-footer {border-top:1px solid rgba(128,128,128,.15);margin-top:.45rem;padding:.6rem .2rem;
      display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;opacity:.72;font-size:.8rem;}
    .nids-footer a {color:inherit;text-decoration:none;font-weight:700;}
    @media print {
      header, [data-testid="stSidebar"], [data-testid="stToolbar"],
      [data-testid="stDecoration"], [data-testid="stStatusWidget"],
      div[data-baseweb="tab-list"], button, .nids-footer {display:none!important;}
      [data-testid="stAppViewContainer"], [data-testid="stMain"] {background:#fff!important;color:#000!important;}
      .block-container {max-width:none!important;padding:0.35in!important;}
      [data-testid="stMainBlockContainer"] > [data-testid="stVerticalBlock"] {min-height:auto!important;}
      .nids-hero {box-shadow:none!important;break-inside:avoid;}
    }
    @media (min-height:750px) {
      .nids-hero {padding:14px 20px;margin-bottom:.8rem;}
      .nids-hero-logo {width:100px;height:100px;}
      .nids-credits-title {margin:.75rem 0 .6rem;}
      .nids-contributor-card {padding:.9rem 1rem;min-height:225px;}
      .nids-contributor-responsibilities {line-height:1.42;margin:.68rem 0 .72rem;}
      .nids-contributor-responsibilities strong {margin-bottom:.3rem;}
      .nids-contributor-responsibilities li {margin:.16rem 0;}
      .nids-credits-scope {margin:.72rem 0 .3rem;padding:.6rem .8rem;line-height:1.42;}
      .st-key-credits_footer_actions {margin-top:.3rem!important;}
      .nids-footer {margin-top:1.1rem;padding:.8rem .2rem;}
    }
    @media (max-width:700px) {
      .nids-dialog-brand {grid-template-columns:76px auto;column-gap:.8rem;
        margin-left:0;}
      .nids-dialog-brand img {width:76px;height:76px;}
      .nids-hero {padding:16px 14px!important;gap:12px!important;}
      .nids-hero-logo {width:86px;height:86px;margin-left:0;}
      .nids-auth-shell {padding:1rem .8rem;margin-top:.75rem;}
      .nids-auth-logo {width:108px;height:108px;}
      .st-key-top_notifications {right:3.65rem;}
      .nids-contributors-grid {grid-template-columns:1fr;}
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def _asset_base64(path):
    """Read a local image for reliable inline rendering."""
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")


def _logo_data_uri():
    """Read the canonical transparent PNG for inline rendering.

    Embedding keeps the logo available in the hero and dialogs without
    requiring Streamlit to expose a static asset route.
    """
    return _asset_base64(_LOGO_PATH)


_logo_b64 = _logo_data_uri()
_sufiyan_avatar_b64 = _asset_base64(
    os.path.join(_CONTRIBUTOR_IMAGE_DIR, "sufiyanaasim.png")
)
_taha_avatar_b64 = _asset_base64(
    os.path.join(_CONTRIBUTOR_IMAGE_DIR, "13eecoder.png")
)


def _dialog_brand_header():
    """Render the shared Cipher identity at the top of project dialogs."""
    logo = (
        f'<img src="data:image/png;base64,{_logo_b64}" alt="{PRODUCT_NAME} logo"/>'
        if _logo_b64 else ""
    )
    st.markdown(
        f"""<div class="nids-dialog-brand">{logo}<div>
        <div class="nids-dialog-title">{PRODUCT_NAME}</div>
        <div class="nids-dialog-meta">{RELEASE_CODENAME} · Version {NIDS_VERSION}</div>
        </div></div>""",
        unsafe_allow_html=True,
    )


@st.dialog("About this project", width="large")
def show_about_dialog():
    """Show the concise project summary without navigating away from the app."""
    _dialog_brand_header()
    st.markdown(
        f"""
        **S-NIDS v{NIDS_VERSION}** compares Random Forest, Decision Tree, and
        optional Isolation Forest analysis on the same live or uploaded
        traffic, then adds consensus risk triage and persistent evidence.

        Cipher's policy-governed autonomy layer correlates high-confidence
        evidence, supports reviewed approvals, and can apply time-bound,
        reversible containment only inside explicit server guardrails.

        It is an operator-support Smart Network Intrusion Detection System, not a
        replacement for a production IDS. Full documentation lives in `docs/`.
        """
    )
    st.markdown("### Built with")
    st.caption(
        "Streamlit · scikit-learn · Scapy · pandas · Altair · SQLite · "
        "reportlab · cryptography"
    )


def render_credits():
    """Render contributor ownership and project credits as a first-class view."""
    st.markdown(
        f"""
        <div class="nids-credits-title">Contributors</div>
        <div class="nids-contributors-grid">
          <section class="nids-contributor-card">
            <div class="nids-contributor-head">
              <a href="https://github.com/SufiyanAasim" target="_blank"
                aria-label="Open SufiyanAasim on GitHub">
                <img class="nids-avatar" src="data:image/png;base64,{_sufiyan_avatar_b64}"
                  alt="SufiyanAasim GitHub profile picture"/>
              </a>
              <div class="nids-contributor-identity">
                <div class="nids-contributor-name">SufiyanAasim</div>
                <span class="nids-contributor-domain">DATA SCIENCES</span>
                <a href="mailto:sufiyanaasim@outlook.com">sufiyanaasim@outlook.com</a>
              </div>
            </div>
            <div class="nids-contributor-responsibilities">
              <strong>Responsibilities</strong>
              <ul>
                <li>AI/ML Ops, models, triage, dashboard, storage, and REST API</li>
                <li>Builds, CI/CD, testing, and software quality</li>
              </ul>
            </div>
            <a class="nids-github-action" href="https://github.com/SufiyanAasim"
              target="_blank">GitHub · @SufiyanAasim</a>
          </section>
          <section class="nids-contributor-card">
            <div class="nids-contributor-head">
              <a href="https://github.com/13eeCoder" target="_blank"
                aria-label="Open 13eeCoder on GitHub">
                <img class="nids-avatar" src="data:image/png;base64,{_taha_avatar_b64}"
                  alt="13eeCoder GitHub profile picture"/>
              </a>
              <div class="nids-contributor-identity">
                <div class="nids-contributor-name">13eeCoder</div>
                <span class="nids-contributor-domain">CYBERSECURITY</span>
                <a href="mailto:tahasiddiqui2100@gmail.com">tahasiddiqui2100@gmail.com</a>
              </div>
            </div>
            <div class="nids-contributor-responsibilities">
              <strong>Responsibilities</strong>
              <ul>
                <li>Networking, capture, traffic analysis, and feature engineering</li>
                <li>Npcap/libpcap, alerts, cryptography, and response controls</li>
              </ul>
            </div>
            <a class="nids-github-action" href="https://github.com/13eeCoder"
              target="_blank">GitHub · @13eeCoder</a>
          </section>
        </div>
        <div class="nids-credits-scope"><strong>Dataset and scope · </strong>
          Models are trained on <strong>NSL-KDD</strong>, a cleaned revision of KDD Cup 1999.
          See the <a href="https://www.unb.ca/cic/datasets/nsl.html" target="_blank">dataset page</a>
          and <code>docs/DATASET.md</code>. Live verdicts are operator-support evidence,
          not a replacement for a production IDS.
        </div>
        """,
        unsafe_allow_html=True,
    )
    with st.container(key="credits_footer_actions"):
        col_btn, col_lic = st.columns([2, 3], vertical_alignment="center")
        with col_btn:
            if st.button(
                "About This Project",
                icon=":material/info:",
                key="credits_about_project",
                width="stretch",
            ):
                show_about_dialog()
        with col_lic:
            st.caption("MIT Licence · © 2026 S-NIDS Contributors · Smart Network Intrusion Detection System")


def _require_login():
    """Gate the app behind a login form when auth is configured.

    No-op (returns immediately) when NIDS_AUTH_PASSWORD_HASH is unset, so the
    app stays open by default. When configured, an unauthenticated session
    sees only the login form and the rest of the script is halted via
    st.stop().
    """
    config_error = auth.configuration_error()
    if config_error:
        st.error(f"Authentication configuration error: {config_error}. Access is disabled.")
        st.stop()
    if not auth.is_auth_configured() and not auth.signup_enabled():
        if os.environ.get("RENDER"):
            st.error("Security alert: `NIDS_AUTH_PASSWORD_HASH` is not set. Configure a password hash before running S-NIDS on Render.")
            st.stop()
        return
    if st.session_state.get("authenticated"):
        return

    logo = (
        f'<img class="nids-auth-logo" src="data:image/png;base64,{_logo_b64}" alt="S-NIDS logo"/>'
        if _logo_b64 else ""
    )
    st.markdown(
        f'<div class="nids-auth-shell">{logo}<div class="nids-auth-title">{PRODUCT_NAME}</div>'
        f'<div class="nids-auth-meta">{RELEASE_CODENAME} · v{NIDS_VERSION} · Secure operator access</div></div>',
        unsafe_allow_html=True,
    )

    if "auth_screen" not in st.session_state:
        st.session_state.auth_screen = "signin"
    with st.container(key="auth_primary_nav"):
        nav_signin, nav_signup = st.columns(2)
        if nav_signin.button("Sign In", icon=":material/login:", width="stretch", type="primary" if st.session_state.auth_screen == "signin" else "secondary"):
            st.session_state.auth_screen = "signin"
            st.rerun()
        signup_available = auth.signup_enabled()
        if nav_signup.button("Create Account", icon=":material/person_add:", width="stretch", disabled=not signup_available,
                             type="primary" if st.session_state.auth_screen == "signup" else "secondary"):
            st.session_state.auth_screen = "signup"
            st.rerun()

    notice = st.session_state.pop("auth_notice", None)
    if notice:
        st.success(notice)

    if st.session_state.auth_screen == "signup" and signup_available:
        st.subheader("Create a Viewer account")
        st.info("New accounts receive the **Viewer** role. Administrator accounts are provisioned securely through configuration.")
        with st.form("signup_form", clear_on_submit=True):
            new_username = st.text_input("Choose a username", autocomplete="username")
            new_password = st.text_input("Choose a password", type="password", autocomplete="new-password")
            confirm_password = st.text_input("Confirm password", type="password", autocomplete="new-password")
            signup_submitted = st.form_submit_button("Create Viewer Account", width="stretch", type="primary")
        if signup_submitted:
            if new_password != confirm_password:
                st.error("Passwords do not match.")
            else:
                created, message = auth.register_viewer(new_username, new_password)
                if created:
                    st.session_state.auth_screen = "signin"
                    st.session_state.selected_login_role = auth.ROLE_VIEWER
                    st.session_state.login_username = new_username.strip()
                    st.session_state.auth_notice = message
                    st.rerun()
                else:
                    st.error(message)
    else:
        st.subheader("Choose access type")
        selected_role = st.session_state.get("selected_login_role")
        admin_users = auth.configured_usernames(auth.ROLE_ADMIN)
        viewer_users = auth.configured_usernames(auth.ROLE_VIEWER)
        admin_choice, viewer_choice = st.columns(2)
        if admin_choice.button(
            "Administrator",
            icon=":material/admin_panel_settings:",
            width="stretch",
            disabled=not admin_users,
            type="primary" if selected_role == auth.ROLE_ADMIN else "secondary",
            key="choose_admin_login",
        ):
            st.session_state.selected_login_role = auth.ROLE_ADMIN
            st.session_state.login_username = ""
            st.session_state.pop("login_password", None)
            st.rerun()
        if viewer_choice.button(
            "Viewer",
            icon=":material/visibility:",
            width="stretch",
            disabled=not viewer_users,
            type="primary" if selected_role == auth.ROLE_VIEWER else "secondary",
            key="choose_viewer_login",
        ):
            st.session_state.selected_login_role = auth.ROLE_VIEWER
            st.session_state.login_username = ""
            st.session_state.pop("login_password", None)
            st.rerun()
        st.markdown(
            '<div class="nids-auth-role-help">Administrator has protected export and backup access. '
            'Viewer is read-only for protected evidence. Select a role, then enter that account\'s credentials.</div>',
            unsafe_allow_html=True,
        )

        selected_role = st.session_state.get("selected_login_role")
        if selected_role:
            selected_label = "Administrator" if selected_role == auth.ROLE_ADMIN else "Viewer"
            st.subheader(f"{selected_label} sign in")
            with st.form("login_form"):
                username = st.text_input(
                    "Username", key="login_username", autocomplete="username"
                )
                password = st.text_input(
                    "Password", key="login_password", type="password",
                    autocomplete="current-password"
                )
                submitted = st.form_submit_button(
                    f"Sign In as {selected_label}", width="stretch", type="primary"
                )
        else:
            st.info("Select Administrator or Viewer to open the matching sign-in form.")
            submitted = False
            username = ""
            password = ""

        if submitted:
            locked, remaining = auth.is_locked_out(username)
            if locked:
                st.error(f"Account locked after repeated failed attempts. Try again in {remaining} seconds.")
            else:
                role = auth.authenticate(username, password)
                if role is not None and role == selected_role:
                    st.session_state["authenticated"] = True
                    st.session_state["user_role"] = role
                    st.session_state["user_name"] = username
                    st.rerun()
                elif role is not None:
                    expected_label = "Administrator" if role == auth.ROLE_ADMIN else "Viewer"
                    st.error(f"This account uses {expected_label} access. Select the matching access type above.")
                else:
                    now_locked, now_remaining = auth.is_locked_out(username)
                    if now_locked:
                        st.error(f"Account locked after repeated failed attempts. Try again in {now_remaining} seconds.")
                    else:
                        st.error("Invalid username or password.")

    st.stop()


_require_login()


def current_role():
    """The signed-in user's role, or None when auth is disabled."""
    return st.session_state.get("user_role")


def is_admin_user():
    """True if the current session may perform admin-only actions."""
    return auth.is_admin(current_role())


def _access_identity():
    """Return a user-facing role label and concise permission summary."""
    if not auth.is_auth_configured():
        return "Local owner", "Full access · sign-in is not configured"
    role = current_role() or auth.ROLE_VIEWER
    if role == auth.ROLE_ADMIN:
        return "Administrator", "Monitor, investigate, export, and back up evidence"
    return "Viewer", "Monitor and investigate · protected exports are read-only"


def _autonomy_mode():
    """Return the session mode, seeded from immutable server policy."""
    default_mode = autonomy.policy_from_env().mode
    mode = st.session_state.get("autonomy_mode", default_mode)
    return mode if mode in autonomy.MODES else autonomy.MODE_SHADOW


def _autonomy_actor():
    return st.session_state.get("user_name") or "local-owner"


# TTL rollback is a control-plane duty, not a page-view side effect. Run it on
# every authenticated app tick when execution is enabled; the operation is
# idempotent and only touches active actions whose expiry has passed.
if autonomy.policy_from_env().execution_enabled:
    autonomy.expire_actions()


@st.dialog("Access and permissions", width="large")
def show_access_dialog():
    """Explain the active role and the admin/viewer authorization boundary."""
    _dialog_brand_header()
    role_name, role_summary = _access_identity()
    st.markdown(f"### {role_name}")
    st.caption(role_summary)
    st.markdown("#### Role permissions")
    st.dataframe(
        pd.DataFrame(
            [
                ("View dashboard and model evidence", "Allowed", "Allowed"),
                ("Analyze live traffic and PCAP files", "Allowed", "Allowed"),
                ("Browse recent history and triage", "Allowed", "Allowed"),
                ("Export the complete history", "Allowed", "Restricted"),
                ("Download an encrypted DB backup", "Allowed", "Restricted"),
            ],
            columns=["Capability", "Administrator", "Viewer"],
        ),
        hide_index=True,
        width="stretch",
    )
    if auth.is_auth_configured():
        st.info(
            "Roles come from `NIDS_AUTH_USERS`. The signed-in role is enforced "
            "for protected history exports and encrypted backups."
        )
    else:
        st.info(
            "Authentication is currently off, so this local session has full "
            "owner access. Configure `NIDS_AUTH_USERS` to enable separate "
            "administrator and viewer sign-ins."
        )
    st.caption(
        "Password hashes are PBKDF2-SHA256 values. Generate one with "
        "`python src/nids/auth.py`; never store plaintext passwords in `.env`."
    )


def _dataframe_to_excel_bytes(df):
    """Serialize a DataFrame to .xlsx bytes, or None if openpyxl is missing.

    Excel export is optional — if the openpyxl engine isn't installed the
    UI just hides the Excel button and keeps CSV, rather than erroring.
    """
    try:
        buffer = io.BytesIO()
        with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="detections")
        return buffer.getvalue()
    except ImportError:
        return None


def render_product_hero():
    """Render the full product identity only where deliberate branding is useful."""
    hero_logo = (
        f'<img class="nids-hero-logo" src="data:image/png;base64,{_logo_b64}" '
        'alt="S-NIDS logo"/>' if _logo_b64 else ""
    )
    st.markdown(
        f"""<div class="nids-hero" style="display:flex;align-items:center;gap:20px">
        {hero_logo}<div class="nids-hero-content">
        <h1 style="margin:.15rem 0 .35rem">{PRODUCT_NAME}</h1>
        <div class="nids-subtitle">Policy-governed autonomous defense with three-model evidence, reversible containment and a complete audit trail.</div></div></div>""",
        unsafe_allow_html=True,
    )

# --- 2. Smart Path Finding ---
BASE_DIR = _BASE_DIR
MODELS_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data", "nsl-kdd")

def get_model_path(filename):
    return os.path.join(MODELS_DIR, filename)

def get_data_path(filename):
    return os.path.join(DATA_DIR, filename)

# --- 4. Load Resources ---
@st.cache_resource
def load_resources():
    try:
        rf_model = joblib.load(get_model_path('rf_model.pkl'))
        dt_model = joblib.load(get_model_path('dt_model.pkl'))

        # Optional third model: only present after `python scripts/train_models.py`
        # has been run since Isolation Forest support was added. The app
        # still works with just RF/DT if it's missing.
        iforest_path = get_model_path('iforest_model.pkl')
        iforest_model = joblib.load(iforest_path) if os.path.exists(iforest_path) else None

        columns = MODEL_FEATURES + ['label', 'difficulty_level']

        train_path = get_data_path('KDDTrain+.txt')
        if not os.path.exists(train_path):
            st.error("Critical error: Could not find 'KDDTrain+.txt'")
            st.stop()
        train_df = pd.read_csv(train_path, names=columns)

        encoders = {}
        categorical_cols = ['protocol_type', 'service', 'flag']
        for col in categorical_cols:
            le = LabelEncoder()
            le.fit(train_df[col])
            encoders[col] = le

        test_path = get_data_path('KDDTest+.txt')
        rf_acc, dt_acc, iforest_acc = None, None, None
        if os.path.exists(test_path):
            test_df = pd.read_csv(test_path, names=columns)
            X_test = test_df[MODEL_FEATURES].copy()
            y_test = test_df['label'].apply(lambda x: 0 if x == 'normal' else 1)
            X_test_encoded = preprocess_data(X_test, encoders)
            rf_acc = accuracy_score(y_test, rf_model.predict(X_test_encoded))
            dt_acc = accuracy_score(y_test, dt_model.predict(X_test_encoded))
            if iforest_model is not None:
                iforest_acc = accuracy_score(y_test, anomaly.to_binary(iforest_model.predict(X_test_encoded)))

        return rf_model, dt_model, iforest_model, encoders, rf_acc, dt_acc, iforest_acc

    except FileNotFoundError as e:
        st.error(
            f"Missing file: {e}\n\n"
            "Models live in `models/` and the dataset in `data/nsl-kdd/`. "
            "Run `python scripts/train_models.py` to regenerate the models."
        )
        st.stop()
    except Exception as e:
        # A corrupt or version-mismatched .pkl used to escape as a raw
        # traceback; joblib models are tied to the scikit-learn version they
        # were trained with.
        st.error(
            f"Could not load the models: {type(e).__name__}: {e}\n\n"
            "This usually means the `.pkl` files were trained with a different "
            "scikit-learn version. Re-run `python scripts/train_models.py`."
        )
        st.stop()

rf_model, dt_model, iforest_model, encoders, rf_acc, dt_acc, iforest_acc = load_resources()

# Sidebar branding
if _logo_b64:
    st.sidebar.markdown(
        f'<div class="nids-sidebar-brand"><img src="data:image/png;base64,{_logo_b64}" '
        'alt="S-NIDS logo"/><strong>S-NIDS</strong></div>',
        unsafe_allow_html=True,
    )

role_name, role_summary = _access_identity()
signed_in = st.session_state.get("user_name")
identity_line = f"Signed in as {signed_in}" if signed_in else role_summary
with st.sidebar.container(key="sidebar_access_section"):
    st.markdown('<div class="nids-sidebar-heading">Access</div>', unsafe_allow_html=True)
    with st.container(key="sidebar_access_group"):
        st.markdown(
            f'<div class="nids-role-card"><span class="nids-role-badge">'
            f'{html.escape(role_name)}</span><span class="nids-role-session">'
            f'{html.escape(identity_line)}</span></div>',
            unsafe_allow_html=True,
        )
        if st.button("Role Permissions", icon=":material/badge:", width="stretch"):
            show_access_dialog()

# Compact accuracy rows preserve the sidebar's information without turning each
# value into a full dashboard card.
def _accuracy_label(value):
    return f"{value * 100:.1f}%" if value is not None else "Not measured"


accuracy_rows = [
    ("Random Forest", _accuracy_label(rf_acc)),
    ("Decision Tree", _accuracy_label(dt_acc)),
]
if iforest_model is not None:
    accuracy_rows.append(("Isolation Forest", _accuracy_label(iforest_acc)))
accuracy_markup = "".join(
    f'<div class="nids-accuracy-row"><span>{html.escape(label)}</span><strong>{value}</strong></div>'
    for label, value in accuracy_rows
)
with st.sidebar.container(key="sidebar_models_section"):
    st.markdown(
        '<div class="nids-sidebar-heading">Model accuracy</div>'
        '<div class="nids-model-state">All available models active · informational</div>'
        f'<div class="nids-accuracy-list">{accuracy_markup}</div>',
        unsafe_allow_html=True,
    )
    if iforest_model is None:
        st.caption("Isolation Forest is not installed.")

# Explanations are rendered as always-visible captions rather than Streamlit
# `help=` tooltips: the "?" tooltip could stay stuck on screen after the
# pointer left it, overlapping the controls below. A caption can't get stuck,
# and the guidance is readable without hunting for a hover target.
with st.sidebar.container(key="sidebar_threshold_section"):
    threshold_widget_key = "critical_threshold_pct"
    displayed_threshold = int(
        st.session_state.get(threshold_widget_key, DEFAULT_CRITICAL_THRESHOLD_PCT)
    )
    st.markdown(
        '<div class="nids-sidebar-heading-row">'
        '<div class="nids-sidebar-heading">Critical threshold</div>'
        f'<div class="nids-threshold-value">{displayed_threshold}%</div>'
        '</div>',
        unsafe_allow_html=True,
    )
    critical_threshold_pct = st.slider(
        "Critical threshold",
        min_value=5, max_value=100, value=DEFAULT_CRITICAL_THRESHOLD_PCT, step=5,
        format="%d%%",
        help="Percentage of model-flagged traffic required for a Critical session threshold.",
        label_visibility="collapsed",
        key=threshold_widget_key,
    )

if auth.is_auth_configured() and st.session_state.get("authenticated"):
    with st.sidebar.container(key="sidebar_logout"):
        if st.button("Log Out", icon=":material/logout:", width="stretch"):
            for k in (
                "authenticated", "user_role", "user_name", "selected_login_role",
                "login_username",
            ):
                st.session_state.pop(k, None)
            st.rerun()

with st.container(key="top_notifications"):
    with st.popover("Notifications", icon=":material/notifications:"):
        st.markdown("**Critical-threat alerts**")
        enable_sound_alert = st.checkbox(
            "Play a sound", value=False, key="enable_sound_alert"
        )
        enable_browser_notification = st.checkbox(
            "Show a browser notification",
            value=False,
            key="enable_browser_notification",
        )
        st.caption("Browser permission is requested the first time it is needed.")

def render_block_suggestions(ip):
    """Show copy-paste firewall block rules for a flagged IP (suggestion only).

    Renders nothing for IPs that shouldn't be blocked (loopback/invalid).
    These commands are never executed by the app — the operator reviews and
    applies them manually.
    """
    rules = firewall.block_rule_snippets(ip)
    if not rules:
        return
    with st.expander(f"Suggested block rules for {ip}"):
        st.caption("Review before applying — S-NIDS never runs these for you.")
        for tool, command in rules.items():
            st.markdown(f"**{tool}**")
            st.code(command, language="bash")


# --- 5. AI Summary Generator ---
def generate_smart_summary(df, col_name, model_name, critical_threshold=DEFAULT_CRITICAL_THRESHOLD_PCT):
    """
    Acts as a simulated AI analyst.
    Calculates stats and generates a text summary based on logic.

    `critical_threshold` (0-100) is the % of ATTACK-flagged traffic at or
    above which status escalates to CRITICAL; anything above 0% and below
    it is SUSPICIOUS. Configurable via the sidebar slider.
    """
    total = len(df)
    if total == 0:
        return

    attacks = df[df[col_name] == triage.ATTACK_VERDICT]
    attack_count = len(attacks)
    attack_pct = (attack_count / total) * 100

    st.markdown(f"##### {model_name} assessment")

    if attack_pct == 0:
        st.success(f"**Status: SAFE.** No malicious traffic detected in the last {total} packets. Network behavior appears normal.")
    elif attack_pct < critical_threshold:
        st.warning(f"**Status: SUSPICIOUS.** Detected {attack_count} anomalous packets ({attack_pct:.1f}%). Monitor specific IPs.")
    else:
        # Critical Analysis
        top_victim = attacks['dst_ip'].mode()[0] if not attacks.empty else "Unknown"
        top_attacker = attacks['src_ip'].mode()[0] if not attacks.empty else "Unknown"

        st.error(
            f"**Status: CRITICAL THREAT.**\n\n"
            f"The {model_name} model has flagged **{attack_pct:.1f}%** of traffic as malicious.\n"
            f"- **Primary Target:** {top_victim}\n"
            f"- **Suspected Attacker:** {top_attacker}\n"
            f"- **Recommendation:** Immediate isolation of {top_attacker} is recommended."
        )

        render_block_suggestions(top_attacker)

        cooldown_key = f"last_alert_{model_name}"
        last_alert_at = st.session_state.get(cooldown_key, 0.0)
        if time.time() - last_alert_at >= ALERT_COOLDOWN_SECONDS:
            st.session_state[cooldown_key] = time.time()
            st.toast(f"Critical threat — {model_name} flagged {attack_pct:.1f}% of traffic")
            sent_channels = alerts.send_critical_alert(model_name, attack_pct, top_attacker, top_victim)
            if sent_channels:
                st.caption(f"Alert sent via: {', '.join(sent_channels)}")

            # Client-side sound / browser notification (opt-in from the top bar).
            if enable_sound_alert or enable_browser_notification:
                components.html(
                    notify.alert_html(
                        f"{model_name} flagged {attack_pct:.1f}% of traffic (attacker {top_attacker})",
                        play_sound=enable_sound_alert,
                        browser_notification=enable_browser_notification,
                        nonce=str(st.session_state[cooldown_key]),
                    ),
                    height=0,
                )

def classify(df):
    """Run both models on df and return it with RF/DT Analysis verdict columns.

    Kept separate from display_results so callers (live-capture loop, pcap
    upload) can persist a classified batch to storage without re-classifying
    (and thus re-persisting) the whole rolling display window on every rerun.
    """
    X_clean = df[MODEL_FEATURES].copy()
    X_processed = preprocess_data(X_clean, encoders)

    rf_pred = rf_model.predict(X_processed)
    dt_pred = dt_model.predict(X_processed)

    df_display = df.copy()
    df_display['RF Analysis'] = [
        triage.ATTACK_VERDICT if p == 1 else triage.NORMAL_VERDICT for p in rf_pred
    ]
    df_display['DT Analysis'] = [
        triage.ATTACK_VERDICT if p == 1 else triage.NORMAL_VERDICT for p in dt_pred
    ]

    if iforest_model is not None:
        iforest_pred = iforest_model.predict(X_processed)
        df_display['Anomaly Analysis'] = anomaly.to_verdict(iforest_pred)

    return triage.add_triage_columns(df_display)


MODEL_COLUMN_STYLE = {
    'RF Analysis': {'label': 'Random Forest', 'color': COLOR_RF,
                    'hint': 'Supervised — trained on labelled NSL-KDD attacks.'},
    'DT Analysis': {'label': 'Decision Tree', 'color': COLOR_DT,
                    'hint': 'Supervised — a single interpretable tree.'},
    'Anomaly Analysis': {'label': 'Isolation Forest', 'color': COLOR_IFOREST,
                         'hint': 'Unsupervised — flags outliers vs normal traffic.'},
}


def render_model_column(df_display, verdict_col, model_name, common_cols):
    style = MODEL_COLUMN_STYLE[verdict_col]
    # A coloured rule keyed to the model's palette colour, instead of an
    # info/warning/success box whose colour contradicted the charts below.
    st.markdown(
        f"<div style='border-left:4px solid {style['color']};padding:2px 0 2px 10px;'>"
        f"<strong>{style['label']}</strong></div>",
        unsafe_allow_html=True,
    )
    st.caption(style['hint'])

    # 1. TABLE
    st.dataframe(df_display[common_cols + [verdict_col]], width='stretch')
    st.markdown("---")

    # 2. BAR CHART
    counts = df_display[verdict_col].value_counts().reset_index()
    counts.columns = ['Status', 'Count']
    chart = alt.Chart(counts).mark_bar().encode(
        x=alt.X('Status', title=None),
        y=alt.Y('Count', title='Packets'),
        color=alt.Color('Status', scale=VERDICT_SCALE, legend=None),
        tooltip=['Status', 'Count'],
    ).properties(height=200, title="Threat distribution")
    st.altair_chart(chart, width='stretch')

    # 3. BOX PLOT (Log)
    box_chart = alt.Chart(df_display).mark_boxplot().encode(
        x=alt.X(verdict_col, title=None),
        y=alt.Y('src_bytes', scale=alt.Scale(type='symlog'), title='Packet size (bytes, log)',
                axis=alt.Axis(tickCount=6, format='~s')),
        color=alt.Color(verdict_col, scale=VERDICT_SCALE, legend=None),
    ).properties(height=200, title="Packet size by verdict")
    st.altair_chart(box_chart, width='stretch')

    # 4. SCATTER PLOT (Log-Log)
    scatter_chart = alt.Chart(df_display).mark_circle(size=100).encode(
        x=alt.X('src_bytes', scale=alt.Scale(type='symlog'), title='Packet size (bytes, log)',
                axis=alt.Axis(tickCount=6, format='~s')),
        y=alt.Y('count', scale=alt.Scale(type='symlog'), title='Traffic count (log)',
                axis=alt.Axis(tickCount=6, format='~s')),
        color=alt.Color(verdict_col, scale=VERDICT_SCALE, legend=None),
        tooltip=['src_ip', 'src_bytes', 'count', verdict_col]
    ).properties(height=300, title="Volume vs size").interactive()
    st.altair_chart(scatter_chart, width='stretch')

    # 5. AI SUMMARY
    generate_smart_summary(df_display, verdict_col, model_name, critical_threshold_pct)


def _set_export_panel(key, visible):
    """Open or close an explicit export panel without coupling it to capture."""
    st.session_state[key] = bool(visible)


def _render_export_actions(df_display, key_suffix):
    """Build report files only after the operator explicitly requests them."""
    csv = df_display.to_csv(index=False).encode('utf-8')
    pdf_bytes = reporting.build_report_pdf(df_display)
    dl_csv, dl_pdf = st.columns(2)
    with dl_csv:
        st.download_button(
            "Download CSV", csv, f"report_{key_suffix}.csv", "text/csv",
            key=f"dl_csv_{key_suffix}", width='stretch',
            icon=":material/download:",
        )
    with dl_pdf:
        if pdf_bytes is not None:
            st.download_button(
                "Download PDF Report", pdf_bytes,
                f"report_{key_suffix}.pdf", "application/pdf",
                key=f"dl_pdf_{key_suffix}", width='stretch',
                icon=":material/picture_as_pdf:",
            )
        else:
            st.caption("PDF export needs `reportlab`.")
def display_results(df, key_suffix="", show_exports=True):
    st.divider()
    try:
        df_display = classify(df)

        critical_count = int((df_display["Triage"] == triage.TRIAGE_CRITICAL).sum())
        elevated_count = int((df_display["Triage"] == triage.TRIAGE_ELEVATED).sum())
        t1, t2, t3 = st.columns(3)
        t1.metric("Consensus risk", f"{df_display['Risk Score'].mean():.0f}/100")
        t2.metric("Critical consensus", critical_count)
        t3.metric("Elevated consensus", elevated_count)
        st.caption(
            "Consensus is an operator-prioritization layer: it counts ATTACK votes "
            "from the models available for this batch; it does not replace their raw verdicts."
        )

        if show_exports:
            _render_export_actions(df_display, key_suffix)

        common_cols = ['src_ip', 'flag', 'count', 'serror_rate', 'src_bytes']
        model_columns = [('RF Analysis', 'Random Forest'), ('DT Analysis', 'Decision Tree')]
        if 'Anomaly Analysis' in df_display.columns:
            model_columns.append(('Anomaly Analysis', 'Isolation Forest'))

        for col, (verdict_col, model_name) in zip(st.columns(len(model_columns)), model_columns):
            with col:
                render_model_column(df_display, verdict_col, model_name, common_cols)

    except Exception as e:
        # Keep the message human, but don't throw the diagnostics away — the
        # bare "Error: <msg>" made real failures (schema drift, model/feature
        # mismatch) impossible to debug from the UI.
        st.error(f"Could not analyse this traffic: {type(e).__name__}: {e}")
        with st.expander("Technical details"):
            st.code(traceback.format_exc(), language="text")


def _render_live_print_button():
    """Expose browser printing only in the Live Capture header."""
    if st.button(
        "Print",
        icon=":material/print:",
        key="live_capture_print",
        width="stretch",
    ):
        components.html(reporting.browser_print_script(str(time.time_ns())), height=0)


def _render_screen_record_control():
    """Render a self-contained browser screen recorder for Live Capture."""
    components.html(
        """
        <style>
        html, body { margin: 0; background: transparent; font-family: sans-serif; }
        button { width: 100%; height: 40px; border: 1px solid #0e7490;
          border-radius: 8px; color: #fff; background: #0e7490; cursor: pointer;
          font-weight: 600; display: flex; align-items: center; justify-content: center;
          gap: 8px; }
        button:hover { border-color: #155e75; background: #155e75; color: #fff; }
        button.active { border-color: #b91c1c; background: #b91c1c; color: #fff; }
        .dot { width: 10px; height: 10px; border: 2px solid currentColor;
          border-radius: 50%; box-sizing: border-box; }
        button.active .dot { border-radius: 2px; background: currentColor; }
        </style>
        <button id="record" type="button"><span class="dot"></span><span>Record Screen</span></button>
        <script>
        const host = window.parent;
        const button = document.getElementById('record');
        const label = button.querySelector('span:last-child');
        function sync() {
          const active = !!(host.__nidsScreenRecorder &&
            host.__nidsScreenRecorder.state === 'recording');
          button.classList.toggle('active', active);
          label.textContent = active ? 'Stop Recording' : 'Record Screen';
        }
        async function stopAndSave() {
          const recorder = host.__nidsScreenRecorder;
          if (recorder && recorder.state !== 'inactive') recorder.stop();
          if (host.__nidsScreenStream) {
            host.__nidsScreenStream.getTracks().forEach(track => track.stop());
          }
          sync();
        }
        button.addEventListener('click', async () => {
          if (host.__nidsScreenRecorder && host.__nidsScreenRecorder.state === 'recording') {
            stopAndSave();
            return;
          }
          try {
            const stream = await host.navigator.mediaDevices.getDisplayMedia({video: true, audio: false});
            const chunks = [];
            const recorder = new host.MediaRecorder(stream, {mimeType: 'video/webm'});
            host.__nidsScreenStream = stream;
            host.__nidsScreenRecorder = recorder;
            recorder.ondataavailable = event => { if (event.data.size) chunks.push(event.data); };
            recorder.onstop = () => {
              if (chunks.length) {
                const url = host.URL.createObjectURL(new host.Blob(chunks, {type: 'video/webm'}));
                const link = host.document.createElement('a');
                link.href = url;
                link.download = `nids-capture-${new Date().toISOString().replace(/[:.]/g, '-')}.webm`;
                link.click();
                setTimeout(() => host.URL.revokeObjectURL(url), 1000);
              }
              host.__nidsScreenRecorder = null;
              host.__nidsScreenStream = null;
              sync();
            };
            stream.getVideoTracks()[0].addEventListener('ended', () => {
              if (recorder.state !== 'inactive') recorder.stop();
            });
            recorder.start(1000);
            sync();
          } catch (error) {
            if (error.name !== 'NotAllowedError') alert(`Screen recording could not start: ${error.message}`);
          }
        });
        sync();
        </script>
        """,
        height=42,
    )


def _live_throughput_chart():
    """Build the current 60-second throughput chart, when enough data exists."""
    agg = throughput.aggregate_per_second(st.session_state.throughput_samples)
    if len(agg) < 2:
        agg_long = pd.DataFrame(columns=["ago", "Metric", "Rate"])
    else:
        agg = agg.copy()
        agg["ago"] = agg["second"] - agg["second"].max()
        agg_long = agg.melt(
            id_vars=["ago"], value_vars=["packets", "kbytes"],
            var_name="Metric", value_name="Rate",
        )
        agg_long["Metric"] = agg_long["Metric"].map(
            {"packets": "Packets/sec", "kbytes": "KB/sec"}
        )
    return alt.Chart(agg_long).mark_area(opacity=0.5).encode(
        x=alt.X("ago:Q", title="Seconds ago", scale=alt.Scale(domain=[-60, 0])),
        y=alt.Y("Rate:Q", title="Rate"),
        color=alt.Color(
            "Metric:N", title=None,
            scale=alt.Scale(
                domain=["Packets/sec", "KB/sec"],
                range=[COLOR_NORMAL, COLOR_IFOREST],
            ),
        ),
        tooltip=[
            alt.Tooltip("ago:Q", title="Seconds ago"),
            "Metric:N",
            alt.Tooltip("Rate:Q", format=".1f"),
        ],
    ).properties(height=180, title="Live throughput (last 60s)")


def _render_dashboard_analytics(df):
    """Render session-level analytics distinct from the live capture monitor."""
    try:
        data = classify(df)
    except Exception as exc:
        st.error(f"Dashboard analytics could not be prepared: {type(exc).__name__}: {exc}")
        return None

    total = len(data)
    critical = int((data["Triage"] == triage.TRIAGE_CRITICAL).sum())
    avg_risk = float(data["Risk Score"].mean()) if total else 0.0
    unique_sources = int(data["src_ip"].nunique()) if "src_ip" in data else 0
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Session observations", total)
    k2.metric("Unique sources", unique_sources)
    k3.metric("Critical consensus", critical)
    k4.metric("Average risk", f"{avg_risk:.1f}/100")

    triage_counts = data["Triage"].value_counts().rename_axis("Triage").reset_index(name="Count")
    triage_order = [
        triage.TRIAGE_CLEAR,
        triage.TRIAGE_GUARDED,
        triage.TRIAGE_ELEVATED,
        triage.TRIAGE_CRITICAL,
    ]
    triage_colors = ["#00CC96", "#7DD3FC", "#FFB84C", "#EF553B"]
    triage_chart = alt.Chart(triage_counts).mark_arc(innerRadius=38, outerRadius=60).encode(
        theta=alt.Theta("Count:Q"),
        color=alt.Color(
            "Triage:N",
            scale=alt.Scale(domain=triage_order, range=triage_colors),
            legend=alt.Legend(
                title=None,
                orient="right",
                symbolSize=50,
                labelLimit=90,
            ),
        ),
        tooltip=["Triage:N", "Count:Q"],
    ).properties(height=theme.CHART_HEIGHT["donut"], title="Consensus triage mix")

    # Every model gets a row, even if its column is missing from this batch
    # (model not loaded) rather than silently dropping its bar — "not loaded"
    # is visually and textually distinct from a genuine 0% attack rate.
    model_rows = []
    for verdict_col, style in MODEL_COLUMN_STYLE.items():
        loaded = verdict_col in data
        attack_rate = float((data[verdict_col] == triage.ATTACK_VERDICT).mean() * 100) if loaded else 0.0
        model_rows.append({
            "Model": style["label"],
            "Attack rate": attack_rate,
            "Loaded": loaded,
            "Label": f"{attack_rate:.0f}%" if loaded else "not loaded",
        })
    model_rates = pd.DataFrame(model_rows)
    model_bar = alt.Chart(model_rates).mark_bar(cornerRadiusEnd=5).encode(
        x=alt.X("Attack rate:Q", title="Flagged as attack (%)", scale=alt.Scale(domain=[0, 100])),
        y=alt.Y("Model:N", title=None, sort=None),
        color=alt.condition(
            alt.datum.Loaded,
            alt.Color(
                "Model:N",
                scale=alt.Scale(
                    domain=["Random Forest", "Decision Tree", "Isolation Forest"],
                    range=[COLOR_RF, COLOR_DT, COLOR_IFOREST],
                ),
                legend=None,
            ),
            alt.value("rgba(128,128,128,.28)"),
        ),
        tooltip=["Model:N", alt.Tooltip("Attack rate:Q", format=".1f"), "Loaded:N"],
    )
    model_text = alt.Chart(model_rates).mark_text(align="left", dx=4).encode(
        x=alt.X("Attack rate:Q"),
        y=alt.Y("Model:N", sort=None),
        text="Label:N",
    )
    model_chart = (model_bar + model_text).properties(
        height=theme.CHART_HEIGHT["card_chart"], title="Model attack-rate comparison"
    )

    # Risk Score is a discrete vote-ratio score (0/33/67/100, or 0/50/100 with
    # two models) per triage.py, not a continuous measure — binning it into
    # arbitrary histogram buckets produced mostly-empty bins and an odd
    # trailing tick. An ordinal axis gives each real value its own bar.
    risk_chart = alt.Chart(data).mark_bar(color=COLOR_DT).encode(
        x=alt.X("Risk Score:O", title="Consensus risk score"),
        y=alt.Y("count():Q", title="Observations", axis=alt.Axis(titleAngle=0, titleAlign="left", titleY=-10)),
        tooltip=[alt.Tooltip("count():Q", title="Observations")],
    ).properties(
        height=theme.CHART_HEIGHT["card_chart"], title="Risk-score distribution",
        padding={"right": 20},
    )

    all_sources = data["src_ip"].nunique() if "src_ip" in data else 0
    source_summary = (
        data.groupby("src_ip", as_index=False)
        .agg(Observations=("src_ip", "size"), **{"Average risk": ("Risk Score", "mean")})
        .sort_values(["Observations", "Average risk"], ascending=False)
        .head(8)
    )
    # A right-side gradient legend (vs. the old bottom/horizontal one) leaves
    # more of the chart's declared height available to the category bands
    # themselves, since Streamlit's altair_chart fits legend+axis+title
    # chrome inside the declared height rather than padding beyond it.
    source_chart = alt.Chart(source_summary).mark_bar(cornerRadiusEnd=4).encode(
        x=alt.X("Observations:Q", title="Observations"),
        y=alt.Y("src_ip:N", title=None, sort="-x", axis=alt.Axis(labelLimit=100)),
        color=alt.Color(
            "Average risk:Q",
            scale=alt.Scale(domain=[0, 100], range=[COLOR_NORMAL, COLOR_ATTACK]),
            title="Average risk",
            legend=alt.Legend(orient="right", gradientLength=100),
        ),
        tooltip=["src_ip:N", "Observations:Q", alt.Tooltip("Average risk:Q", format=".1f")],
    ).properties(
        height=theme.dynamic_height(len(source_summary)), title="Most active source IPs"
    )

    with st.container(key="dashboard_chart_grid"):
        chart_left, chart_right = st.columns(2, gap="medium", vertical_alignment="top")
        with chart_left:
            with st.container(border=True, key="dashboard_triage_card"):
                st.altair_chart(triage_chart, width="stretch")
        with chart_right:
            with st.container(border=True, key="dashboard_model_card"):
                st.altair_chart(model_chart, width="stretch")

        risk_left, source_right = st.columns(2, gap="medium", vertical_alignment="top")
        with risk_left:
            with st.container(border=True, key="dashboard_risk_card"):
                st.altair_chart(risk_chart, width="stretch")
        with source_right:
            with st.container(border=True, key="dashboard_sources_card"):
                st.altair_chart(source_chart, width="stretch")
                if all_sources > 8:
                    st.caption(f"Showing top 8 of {all_sources} source IPs.")

    with st.expander("Recent session evidence"):
        evidence_columns = [
            column for column in
            ["src_ip", "Triage", "Risk Score", "RF Analysis", "DT Analysis", "Anomaly Analysis"]
            if column in data
        ]
        st.dataframe(data[evidence_columns].tail(25), width="stretch", hide_index=True)
    return data

# --- 7. UI Layout ---
if 'raw_packets' not in st.session_state:
    st.session_state.raw_packets = []
if 'continuous_df' not in st.session_state:
    st.session_state.continuous_df = pd.DataFrame()
if 'is_running' not in st.session_state:
    st.session_state.is_running = False
if 'total_captured' not in st.session_state:
    st.session_state.total_captured = 0
if 'throughput_samples' not in st.session_state:
    st.session_state.throughput_samples = []

dashboard_tab, live_tab, upload_tab, model_tab, autonomy_tab, history_tab, credits_tab = st.tabs(
    ["Dashboard", "Live Capture", "Upload PCAP", "Model Logic", "Autonomy", "History", "Credits"]
)

# === TAB 1: Dashboard ===
with dashboard_tab:
    dashboard_export_key = "exports_ready_dashboard"
    dashboard_title_column, dashboard_export_column = st.columns(
        [4, 1], vertical_alignment="center"
    )
    with dashboard_title_column:
        st.subheader("Detection Dashboard")
    with dashboard_export_column:
        if not st.session_state.continuous_df.empty:
            with st.container(key="dashboard_export_control"):
                dashboard_exports_open = bool(st.session_state.get(dashboard_export_key))
                st.button(
                    "Close Report Exports" if dashboard_exports_open else "Prepare Report Exports",
                    icon=":material/close:" if dashboard_exports_open else ":material/file_export:",
                    key="toggle_exports_dashboard",
                    on_click=_set_export_panel,
                    args=(dashboard_export_key, not dashboard_exports_open),
                    width="stretch",
                )

    if st.session_state.continuous_df.empty:
        st.info(
            "No live session evidence yet. Open **Live Capture** to start monitoring, "
            "or use **Upload PCAP** to analyse a saved capture."
        )
    else:
        st.caption(
            "Session analytics · Capture is "
            f"**{'running' if st.session_state.is_running else 'paused'}** · "
            f"{st.session_state.total_captured} packets captured"
        )
        dashboard_data = _render_dashboard_analytics(st.session_state.continuous_df)
        if dashboard_data is not None and st.session_state.get(dashboard_export_key):
            _render_export_actions(dashboard_data, "dashboard")

# === TAB 2: Live Capture ===
with live_tab:
    title_column, title_print_column, title_record_column = st.columns(
        [3, 1, 1], vertical_alignment="center"
    )
    with title_column:
        st.subheader("Live Network Sniffer")
    with title_print_column:
        with st.container(key="live_print_control"):
            _render_live_print_button()
    with title_record_column:
        with st.container(key="live_record_control"):
            _render_screen_record_control()

    def set_capture_running(running):
        """Update capture state before Streamlit renders the next widget tree."""
        st.session_state.is_running = bool(running)
        if running:
            st.session_state.pop("capture_error", None)
        # A capture control must never prepare or trigger report downloads.
        # Closing the panel also avoids rebuilding PDF bytes on live reruns.
        st.session_state.pop("exports_ready_dashboard", None)
        st.session_state.pop("exports_ready_continuous", None)

    capture_ready, capture_message = netcheck.capture_readiness()
    if not capture_ready:
        st.warning(capture_message)
    else:
        st.caption(netcheck.privilege_hint())

    interfaces = netcheck.capture_interfaces() if capture_ready else []
    interface_labels = {item.identifier: item.label for item in interfaces}
    if capture_ready and not interfaces:
        st.warning("No capture adapters were reported by Scapy. Refresh after connecting an adapter or restarting Npcap.")
    default_interface = netcheck.default_capture_interface(interfaces)
    if "capture_interface" not in st.session_state or st.session_state.capture_interface not in interface_labels:
        st.session_state.capture_interface = default_interface

    adapter_column, controls_column = st.columns([2, 3], vertical_alignment="bottom")
    with adapter_column:
        selected_interface = st.selectbox(
            "Capture interface",
            options=list(interface_labels),
            format_func=lambda identifier: interface_labels.get(identifier, identifier),
            key="capture_interface",
            disabled=st.session_state.is_running or not interfaces,
            help="Choose the physical, Wi-Fi, VPN, or virtual adapter that carries the traffic you want to inspect.",
        ) if interfaces else None
    with controls_column:
        start_column, stop_column = st.columns(2)
        with start_column:
            st.button(
                "Start", icon=":material/play_arrow:", width="stretch",
                disabled=not capture_ready or not interfaces or st.session_state.is_running,
                on_click=set_capture_running,
                args=(True,),
            )
        with stop_column:
            st.button(
                "Stop", icon=":material/stop:", width="stretch", disabled=not st.session_state.is_running,
                on_click=set_capture_running,
                args=(False,),
            )

    st.info(
        "**Capture scope — this device:** S-NIDS sees traffic available to the selected adapter "
        "(this computer's traffic plus visible broadcast/multicast). For whole-LAN visibility, "
        "mirror switch traffic with SPAN, use a network TAP, or run the sensor on the gateway/router."
    )
    st.caption(
        f"The packet counter and fixed-height throughput graph refresh every "
        f"**{LIVE_REFRESH_SECONDS:g} seconds** while capturing. Model evidence updates on "
        "Start/Stop transitions. Stop never prepares or downloads a report."
    )

    @st.fragment(run_every=LIVE_REFRESH_SECONDS if st.session_state.is_running else None)
    def capture_counter_fragment():
        """Capture one batch and redraw only the fixed-height packet counter."""
        if st.session_state.is_running:
            pkt_batch = []
            try:
                pkt_batch = sniff(
                    iface=st.session_state.capture_interface,
                    count=LIVE_BATCH_SIZE,
                    timeout=LIVE_SNIFF_TIMEOUT,
                )
            except (OSError, PermissionError, RuntimeError, Scapy_Exception) as exc:
                st.session_state.is_running = False
                st.session_state.capture_error = (
                    f"Live capture stopped: {type(exc).__name__}: {exc}. "
                    f"{netcheck.privilege_hint()}"
                )
                st.rerun()

            if pkt_batch:
                st.session_state.raw_packets.extend(pkt_batch)
                st.session_state.raw_packets = st.session_state.raw_packets[-RAW_PACKET_BUFFER:]
                st.session_state.total_captured += len(pkt_batch)

                now_sec = int(time.time())
                batch_bytes = sum(len(packet) for packet in pkt_batch)
                st.session_state.throughput_samples.append(
                    {"t": now_sec, "packets": len(pkt_batch), "bytes": batch_bytes}
                )
                st.session_state.throughput_samples = throughput.trim_samples(
                    st.session_state.throughput_samples, max_seconds=60, now=now_sec
                )

                windowed_df = packets_to_df(st.session_state.raw_packets)
                st.session_state.continuous_df = windowed_df.tail(100)
                if not st.session_state.continuous_df.empty:
                    new_rows = windowed_df.tail(len(pkt_batch))
                    classified_rows = classify(new_rows)
                    storage.save_detections(classified_rows, source="live")
                    autonomy.record_batch(
                        classified_rows,
                        source="live",
                        mode=_autonomy_mode(),
                        actor=_autonomy_actor(),
                    )

        st.metric("Packets captured this session", st.session_state.total_captured)

    c1, c2 = st.columns([1, 4])
    with c1:
        if selected_interface:
            st.caption(f"Adapter: **{interface_labels[selected_interface]}**")
    with c2:
        capture_counter_fragment()

    capture_error = st.session_state.get("capture_error")
    if capture_error:
        st.error(capture_error)
    elif st.session_state.is_running:
        st.info("**Capturing live traffic.** Use Stop to pause packet intake.")
    elif not st.session_state.continuous_df.empty:
        st.info(
            "Capture is paused. The latest throughput and model evidence are shown below; "
            "Dashboard provides aggregate session analytics."
        )
    elif capture_ready:
        st.info("Ready to monitor. Select Start to begin collecting traffic.")
    else:
        st.info(
            "Live capture is unavailable on this host. Upload PCAP analysis remains available."
        )

    @st.fragment(run_every=LIVE_REFRESH_SECONDS if st.session_state.is_running else None)
    def live_throughput_fragment():
        """Redraw the live chart inside a height-reserved region."""
        st.altair_chart(_live_throughput_chart(), width="stretch")

    with st.container(key="live_throughput_panel"):
        live_throughput_fragment()
    if not st.session_state.continuous_df.empty:
        with st.container(key="live_results_panel"):
            display_results(
                st.session_state.continuous_df,
                "continuous",
                show_exports=False,
            )

# === TAB 3: File Upload (Auto-Clean Logic Added) ===
with upload_tab:
    st.subheader("Analyze .pcap Files")
    st.caption(
        "Upload a Wireshark capture to classify it with all models. "
        "No sample handy? Try the ones in `data/pcaps/` "
        "(`ddos_attack.pcap`, `neptune_attack.pcap`, `mixed_attack.pcap`)."
    )
    uploaded_file = st.file_uploader("Upload .pcap", type=["pcap", "pcapng"], key="file_uploader")

    # CLEANUP: If file is removed, clear session state and reload
    if uploaded_file is None:
        upload_state_keys = ('upload_data', 'last_file', 'last_upload_fingerprint')
        if any(key in st.session_state for key in upload_state_keys):
            for key in upload_state_keys:
                st.session_state.pop(key, None)
            st.rerun()

    # PROCESS: If file exists, process it
    if uploaded_file is not None:
        upload_bytes = uploaded_file.getvalue()
        upload_fingerprint = hashlib.sha256(upload_bytes).hexdigest()
        if len(upload_bytes) > MAX_PCAP_UPLOAD_MB * 1024 * 1024:
            st.error(f"Capture is larger than the {MAX_PCAP_UPLOAD_MB} MB safety limit.")
        elif st.session_state.get('last_upload_fingerprint') != upload_fingerprint:
            with st.spinner("Processing..."):
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                    tmp.write(upload_bytes)
                    tmp_name = tmp.name
                try:
                    packets = rdpcap(tmp_name)
                    upload_df = packets_to_df(packets)
                    st.session_state['upload_data'] = upload_df
                    st.session_state['last_file'] = uploaded_file.name
                    st.session_state['last_upload_fingerprint'] = upload_fingerprint

                    # Persist exactly once per uploaded file (this block only
                    # runs when the filename changes), not on every rerun.
                    if not upload_df.empty:
                        classified_upload = classify(upload_df)
                        storage.save_detections(classified_upload, source="upload")
                        autonomy.record_batch(
                            classified_upload,
                            source="upload",
                            mode=_autonomy_mode(),
                            actor=_autonomy_actor(),
                        )
                except Exception as exc:
                    # Scapy readers raise several parser-specific exception
                    # types for malformed/untrusted captures. Keep all of
                    # them inside the upload boundary and show a safe error.
                    st.session_state.pop('upload_data', None)
                    st.error(f"Could not read this packet capture: {type(exc).__name__}: {exc}")
                finally:
                    try:
                        os.remove(tmp_name)
                    except OSError:
                        pass

    # DISPLAY: Show results if data exists
    if 'upload_data' in st.session_state and not st.session_state['upload_data'].empty:
        display_results(st.session_state['upload_data'], "upload")
    elif 'upload_data' in st.session_state:
        st.info("This capture contains no IPv4 packets that can be classified.")

# === TAB 4: Explainable AI ===
with model_tab:
    st.subheader("Explainable AI")
    st.caption(
        "Which of the 41 NSL-KDD features each supervised model leans on most "
        "when deciding attack vs. normal (top 10 shown)."
    )

    def _importance_chart(model, color):
        imp = pd.DataFrame(
            {'Feature': MODEL_FEATURES, 'Importance': model.feature_importances_}
        ).sort_values('Importance', ascending=False).head(10)
        return alt.Chart(imp).mark_bar().encode(
            x=alt.X('Importance:Q', title='Importance'),
            y=alt.Y('Feature:N', sort='-x', title=None),
            color=alt.value(color),
            tooltip=['Feature:N', alt.Tooltip('Importance:Q', format='.4f')],
        ).properties(height=280)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"<div style='border-left:4px solid {COLOR_RF};padding:2px 0 2px 10px;'>"
                    f"<strong>Random Forest</strong></div>", unsafe_allow_html=True)
        st.altair_chart(_importance_chart(rf_model, COLOR_RF), width='stretch')
    with col2:
        st.markdown(f"<div style='border-left:4px solid {COLOR_DT};padding:2px 0 2px 10px;'>"
                    f"<strong>Decision Tree</strong></div>", unsafe_allow_html=True)
        st.altair_chart(_importance_chart(dt_model, COLOR_DT), width='stretch')

    # Previously this tab silently showed only RF/DT, leaving users to wonder
    # where the third model went.
    if iforest_model is not None:
        st.info(
            "**Isolation Forest** isn't shown here: it's unsupervised and "
            "scores how *isolated* a connection is rather than learning "
            "per-feature attack importances, so scikit-learn exposes no "
            "`feature_importances_` for it."
        )

# === TAB 5: Policy-governed autonomous defense ===
with autonomy_tab:
    st.subheader("Autonomous Defense")
    st.caption(
        "Correlates high-confidence model evidence into reversible response actions. "
        "Shadow is the safe default; host changes require explicit server policy."
    )

    autonomy_policy = autonomy.policy_from_env()
    mode_labels = {
        autonomy.MODE_SHADOW: "Shadow",
        autonomy.MODE_APPROVAL: "Approval",
        autonomy.MODE_AUTONOMOUS: "Autonomous",
    }
    mode_help = {
        autonomy.MODE_SHADOW: "Observe and simulate decisions without applying actions.",
        autonomy.MODE_APPROVAL: "Queue eligible responses for Administrator approval.",
        autonomy.MODE_AUTONOMOUS: "Apply eligible responses only when server execution is enabled.",
    }
    mode_column, guardrail_column = st.columns([1, 2], vertical_alignment="bottom")
    with mode_column:
        current_mode = _autonomy_mode()
        selected_mode = st.selectbox(
            "Operating mode",
            options=list(autonomy.MODES),
            index=list(autonomy.MODES).index(current_mode),
            format_func=lambda value: mode_labels[value],
            disabled=not is_admin_user(),
            key="autonomy_mode_selector",
        )
        if selected_mode != current_mode and is_admin_user():
            st.session_state.autonomy_mode = selected_mode
            st.rerun()
        elif "autonomy_mode" not in st.session_state:
            st.session_state.autonomy_mode = current_mode
    with guardrail_column:
        st.info(
            f"**{mode_labels[_autonomy_mode()]}:** {mode_help[_autonomy_mode()]} "
            f"Minimum evidence: {autonomy_policy.min_events} events at "
            f"risk {autonomy_policy.min_risk}+. Temporary block TTL: "
            f"{autonomy_policy.block_ttl_minutes} minutes."
        )

    if autonomy_policy.execution_enabled:
        st.success(
            "Server-side response execution is enabled. Private sources remain protected "
            "unless NIDS_AUTONOMY_ALLOW_PRIVATE is explicitly enabled."
        )
    else:
        st.warning(
            "Response execution is disabled by server policy. Decisions and approvals are "
            "audited, but no firewall state will change. Set NIDS_AUTONOMY_EXECUTE=true "
            "only after validating Shadow and Approval modes."
        )

    autonomy_summary = autonomy.query_summary()
    a1, a2, a3, a4 = st.columns(4)
    a1.metric("Correlated", autonomy_summary["incidents"])
    a2.metric("Pending", autonomy_summary["pending"])
    a3.metric("Active blocks", autonomy_summary["active"])
    a4.metric("Shadow sims", autonomy_summary["simulated"])

    history_for_drift = storage.query_all()
    drift = autonomy.drift_report(history_for_drift)
    drift_left, drift_right = st.columns([1, 3], vertical_alignment="center")
    with drift_left:
        st.metric("Behavior drift", f"{drift['score']:.1f}/100", drift["status"].title())
    with drift_right:
        if drift["status"] == "learning":
            st.caption("Adaptive baseline is learning; more persisted traffic is required.")
        elif drift["retrain_recommended"]:
            st.warning(
                "Material behavior drift detected. Review evidence and approve an offline "
                "retraining run; production models are never replaced automatically."
            )
        else:
            st.caption(
                "Recent traffic is compared with older persisted behavior. Drift signals "
                "recommend review but cannot silently retrain or replace models."
            )

    pending_actions = autonomy.query_actions(status="pending")
    st.markdown("##### Response approval queue")
    if pending_actions.empty:
        st.caption("No response actions are waiting for approval.")
    else:
        st.dataframe(pending_actions, width="stretch", hide_index=True)
        if is_admin_user():
            selected_action_id = st.selectbox(
                "Pending action",
                pending_actions["id"].astype(int).tolist(),
                format_func=lambda action_id: (
                    f"Action {action_id} · "
                    f"{pending_actions.loc[pending_actions['id'] == action_id, 'target'].iloc[0]}"
                ),
            )
            approve_column, deny_column = st.columns(2)
            if approve_column.button(
                "Approve Response", icon=":material/verified_user:", width="stretch"
            ):
                ok, message = autonomy.decide_action(
                    selected_action_id, "approve", _autonomy_actor(),
                    policy=autonomy_policy,
                )
                (st.success if ok else st.error)(message)
                st.rerun()
            if deny_column.button(
                "Deny Response", icon=":material/block:", width="stretch"
            ):
                ok, message = autonomy.decide_action(
                    selected_action_id, "deny", _autonomy_actor(),
                    policy=autonomy_policy,
                )
                (st.success if ok else st.error)(message)
                st.rerun()
        else:
            st.info("Viewer access can inspect the queue but cannot approve or deny actions.")

    active_actions = autonomy.query_actions(status="active")
    if not active_actions.empty:
        st.markdown("##### Active containment")
        st.dataframe(active_actions, width="stretch", hide_index=True)
        if is_admin_user():
            rollback_id = st.selectbox(
                "Active block",
                active_actions["id"].astype(int).tolist(),
                key="autonomy_rollback_action",
            )
            if st.button(
                "Rollback Selected Block", icon=":material/undo:", width="stretch"
            ):
                ok, message = autonomy.rollback_action(
                    rollback_id, _autonomy_actor()
                )
                (st.success if ok else st.error)(message)
                st.rerun()

    with st.expander("Correlated incidents", expanded=True):
        incidents = autonomy.query_incidents()
        if incidents.empty:
            st.caption("No eligible high-confidence incidents have been correlated yet.")
        else:
            st.dataframe(incidents, width="stretch", hide_index=True)
    with st.expander("Response audit trail"):
        audit_rows = autonomy.query_audit()
        if audit_rows.empty:
            st.caption("No autonomy decisions have been audited yet.")
        else:
            st.dataframe(audit_rows, width="stretch", hide_index=True)

# === TAB 6: History (persisted beyond the in-memory 100-row buffer) ===
with history_tab:
    st.subheader("Detection History")
    try:
        _db_label = os.path.relpath(storage.DEFAULT_DB_PATH, BASE_DIR)
    except ValueError:
        # relpath raises across Windows drives — the packaged build keeps the
        # database under %LOCALAPPDATA% while the bundle lives elsewhere, and
        # NIDS_DB_PATH can point anywhere. Fall back to the absolute path.
        _db_label = storage.DEFAULT_DB_PATH
    st.caption(f"Persisted to `{_db_label}`")

    summary = storage.query_summary()
    total = int(summary["total"] or 0)

    if total == 0:
        st.info("No detections persisted yet. Run a live capture or upload a pcap first.")
    else:
        rf_attacks = int(summary["rf_attacks"] or 0)
        dt_attacks = int(summary["dt_attacks"] or 0)
        anomaly_attacks = int(summary["anomaly_attacks"] or 0)

        critical_triage = int(summary["critical_triage"] or 0)
        avg_risk = float(summary["avg_risk_score"] or 0)

        m1, m2, m3 = st.columns(3)
        m1.metric("Total detections", total)
        m2.metric("RF attacks flagged", rf_attacks, f"{rf_attacks / total * 100:.1f}%")
        m3.metric("DT attacks flagged", dt_attacks, f"{dt_attacks / total * 100:.1f}%")
        m4, m5, m6 = st.columns(3)
        m4.metric("Anomalies flagged", anomaly_attacks, f"{anomaly_attacks / total * 100:.1f}%")
        m5.metric("Critical consensus", critical_triage)
        m6.metric("Average risk", f"{avg_risk:.1f}/100")

        st.markdown("##### Consensus triage queue")
        tq1, tq2 = st.columns([1, 3])
        with tq1:
            min_triage_risk = st.slider(
                "Minimum risk score", 0, 100, 50, 10, key="history_min_triage_risk"
            )
        triage_rows = storage.query_triage(min_risk=min_triage_risk, limit=100)
        with tq2:
            st.caption(
                "Prioritizes detections by agreement across the available models. "
                "Legacy rows remain available in history with no consensus score."
            )
        if triage_rows.empty:
            st.info("No detections meet this consensus risk threshold.")
        else:
            st.dataframe(triage_rows, width='stretch', hide_index=True)

        st.markdown("##### Attacks over time")
        trend_df = storage.query_trend()
        if len(trend_df) >= 2:
            trend_value_vars = ["rf_attacks", "dt_attacks"]
            trend_model_map = {"rf_attacks": "Random Forest", "dt_attacks": "Decision Tree"}
            trend_domain = ["Random Forest", "Decision Tree"]
            trend_range = [COLOR_RF, COLOR_DT]
            if "anomaly_attacks" in trend_df:
                trend_value_vars.append("anomaly_attacks")
                trend_model_map["anomaly_attacks"] = "Isolation Forest"
                trend_domain.append("Isolation Forest")
                trend_range.append(COLOR_IFOREST)
            trend_long = trend_df.melt(
                id_vars=["bucket"], value_vars=trend_value_vars,
                var_name="Model", value_name="Attacks",
            )
            trend_long["Model"] = trend_long["Model"].map(trend_model_map)
            # Real temporal axis: a nominal ("bucket:N") axis rendered one
            # crowded tick per minute and became unreadable as history grew.
            trend_long["bucket"] = pd.to_datetime(trend_long["bucket"], utc=True, errors="coerce")
            trend_chart = alt.Chart(trend_long.dropna(subset=["bucket"])).mark_line(point=True).encode(
                x=alt.X("bucket:T", title="Time (UTC)"),
                y=alt.Y("Attacks:Q", title="Attacks flagged"),
                color=alt.Color(
                    "Model:N", title=None,
                    scale=alt.Scale(domain=trend_domain, range=trend_range),
                ),
                tooltip=[alt.Tooltip("bucket:T", title="Time"), "Model:N", "Attacks:Q"],
            ).properties(height=250)
            st.altair_chart(trend_chart, width='stretch')
        else:
            st.caption("Trend chart needs at least 2 minutes of history — capture more traffic to see it.")

        st.markdown("##### Administrator tools")
        if not is_admin_user():
            st.info(
                "Viewer access is read-only here. Complete-history exports and "
                "encrypted database backups require an administrator account."
            )
            if st.button(
                "Review Role Permissions",
                icon=":material/badge:",
                key="history_permissions",
            ):
                show_access_dialog()
        else:
            st.caption(
                f"Administrator access · download all {total} persisted "
                "detections, not just the view below."
            )
            all_history = storage.query_all()
            exp_csv, exp_xlsx, exp_enc = st.columns(3)
            with exp_csv:
                st.download_button(
                    "CSV (All History)",
                    all_history.to_csv(index=False).encode("utf-8"),
                    "nids_history.csv",
                    "text/csv",
                    width='stretch',
                    icon=":material/download:",
                )
            with exp_xlsx:
                xlsx_bytes = _dataframe_to_excel_bytes(all_history)
                if xlsx_bytes is not None:
                    st.download_button(
                        "Excel (All History)",
                        xlsx_bytes,
                        "nids_history.xlsx",
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        width='stretch',
                        icon=":material/table_view:",
                    )
                else:
                    st.caption("Excel needs `openpyxl`.")
            with exp_enc:
                # Encrypted at-rest backup of the raw DB file (opt-in).
                if not crypto.encryption_available():
                    st.caption("Encrypted backup needs `cryptography`.")
                elif crypto.configured_key() is None:
                    st.caption("Set `NIDS_DB_ENCRYPTION_KEY` to enable encrypted backup.")
                else:
                    enc_bytes = crypto.encrypt_file(storage.DEFAULT_DB_PATH)
                    if enc_bytes is not None:
                        st.download_button(
                            "Encrypted Backup",
                            enc_bytes,
                            "nids_history.db.enc",
                            "application/octet-stream",
                            width='stretch',
                            icon=":material/encrypted:",
                        )

        st.divider()
        st.markdown("##### Source IP geography")
        distinct_ips = storage.query_distinct_ips()
        category_counts = geo.categorize_ips(distinct_ips)
        if category_counts:
            cat_df = pd.DataFrame(
                {"Category": list(category_counts.keys()), "IPs": list(category_counts.values())}
            )
            cat_chart = alt.Chart(cat_df).mark_bar().encode(
                x=alt.X(
                    "IPs:Q",
                    scale=alt.Scale(domain=[0, max(category_counts.values()) + 1]),
                ),
                y=alt.Y("Category:N", sort="-x"),
                color=alt.value("#22D3EE"),
                tooltip=["Category", "IPs"],
            ).properties(height=160, title="Distinct source IPs by type")
            st.altair_chart(cat_chart, width='stretch')

        if geo.geoip_available():
            locations = geo.resolve_locations(distinct_ips)
            if locations:
                map_df = pd.DataFrame(locations).rename(
                    columns={"latitude": "lat", "longitude": "lon"}
                )
                st.map(map_df[["lat", "lon"]])
                st.caption(f"Mapped {len(locations)} public IP(s) via MaxMind GeoIP.")
            else:
                st.caption("No public IPs with a known location in history yet.")
        else:
            public_count = category_counts.get("public", 0)
            st.caption(
                f"{public_count} public IP(s) seen. Set `GEOIP_DB_PATH` to a MaxMind "
                "GeoLite2-City `.mmdb` file and install `geoip2` to plot them on a world map."
            )

        st.divider()
        st.markdown("##### Drill down by source IP")
        st.caption("See every past detection for one source IP across all sessions.")
        ip_options = ["(select an IP)"] + distinct_ips
        selected_ip = st.selectbox("Source IP", ip_options)
        if selected_ip != "(select an IP)":
            ip_summary = storage.query_ip_summary(selected_ip)
            ip_total = int(ip_summary["total"] or 0)
            ip_rf = int(ip_summary["rf_attacks"] or 0)
            ip_dt = int(ip_summary["dt_attacks"] or 0)

            ip_critical = int(ip_summary["critical_triage"] or 0)
            ip_risk = float(ip_summary["avg_risk_score"] or 0)
            d1, d2, d3, d4, d5 = st.columns(5)
            d1.metric("Detections", ip_total)
            d2.metric("RF attacks", ip_rf, f"{(ip_rf / ip_total * 100) if ip_total else 0:.1f}%")
            d3.metric("DT attacks", ip_dt, f"{(ip_dt / ip_total * 100) if ip_total else 0:.1f}%")
            d4.metric("Critical consensus", ip_critical)
            d5.metric("Average risk", f"{ip_risk:.1f}/100")
            st.caption(f"First seen: {ip_summary['first_seen']} · Last seen: {ip_summary['last_seen']} (UTC)")
            render_block_suggestions(selected_ip)
            st.dataframe(storage.query_by_ip(selected_ip), width='stretch')

        st.divider()
        st.markdown("##### Most recent 200 detections")
        sources = ["All"] + storage.query_sources()
        selected_source = st.selectbox("Filter by source", sources)
        source_filter = None if selected_source == "All" else selected_source
        st.dataframe(storage.query_recent(limit=200, source=source_filter), width='stretch')

# === TAB 7: Project ownership and credits ===
with credits_tab:
    render_product_hero()
    render_credits()

st.markdown(
    f'<footer class="nids-footer"><span>{PRODUCT_NAME} · v{NIDS_VERSION} '
    f'({RELEASE_CODENAME})</span><span>Local capture respects adapter visibility · '
    '<a href="https://github.com/SufiyanAasim/smart-network-intrusion-detection-system" '
    'target="_blank">GitHub</a></span></footer>',
    unsafe_allow_html=True,
)
