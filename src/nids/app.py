import base64
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
_LOGO_PATH = os.path.join(_BASE_DIR, "assets", "images", "logo.svg")

import streamlit as st  # noqa: E402
import streamlit.components.v1 as components  # noqa: E402
import pandas as pd  # noqa: E402
import joblib  # noqa: E402
from scapy.all import sniff, rdpcap  # noqa: E402
from sklearn.preprocessing import LabelEncoder  # noqa: E402
from sklearn.metrics import accuracy_score  # noqa: E402
import tempfile  # noqa: E402
import altair as alt  # noqa: E402
import time  # noqa: E402

from nids.features import MODEL_FEATURES, WINDOW_CONNECTIONS, preprocess_data, packets_to_df  # noqa: E402
from nids import storage, alerts, anomaly, geo, reporting, throughput, notify, netcheck, auth, firewall, crypto  # noqa: E402
from nids import __version__ as NIDS_VERSION  # noqa: E402

# Raw packets kept in session_state for live capture, so packets_to_df can
# compute a real trailing window instead of a single-packet snapshot.
RAW_PACKET_BUFFER = WINDOW_CONNECTIONS * 3

# Minimum seconds between two critical-threat alerts for the same model, so a
# sustained attack doesn't spam Slack/email/webhook on every Streamlit rerun.
ALERT_COOLDOWN_SECONDS = int(os.environ.get("ALERT_COOLDOWN_SECONDS", "60"))

# Default CRITICAL threshold (% of traffic flagged as attack) before a
# sidebar slider lets the user adjust it per session. SUSPICIOUS is anything
# above 0% and below this.
DEFAULT_CRITICAL_THRESHOLD_PCT = int(os.environ.get("CRITICAL_THRESHOLD_PCT", "20"))

# Live capture pulls this many packets per script run before rerunning, so the
# Stop button stays responsive (see the Live Capture tab for why).
LIVE_BATCH_SIZE = int(os.environ.get("LIVE_BATCH_SIZE", "5"))
LIVE_SNIFF_TIMEOUT = float(os.environ.get("LIVE_SNIFF_TIMEOUT", "1"))

# One palette for the whole app, so a model reads as the same colour in the
# sidebar, its results column, and the Explainable AI charts.
COLOR_NORMAL = "#00CC96"
COLOR_ATTACK = "#EF553B"
COLOR_RF = "#00CC96"
COLOR_DT = "#FFB84C"
COLOR_IFOREST = "#22D3EE"
VERDICT_SCALE = alt.Scale(domain=['✅ Normal', '🚨 ATTACK'], range=[COLOR_NORMAL, COLOR_ATTACK])

# --- 1. Page Configuration ---
st.set_page_config(page_title="Network Intrusion Detection", page_icon="🛡️", layout="wide")


def _logo_data_uri():
    """Read assets/images/logo.svg and inline it as a base64 data URI.

    Embedding via <img src="data:..."> works regardless of which image
    formats a given Streamlit version's st.image() supports, and needs no
    extra image-processing dependency (PIL/cairosvg) just to show an SVG.
    """
    if not os.path.exists(_LOGO_PATH):
        return None
    with open(_LOGO_PATH, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")


_logo_b64 = _logo_data_uri()


def _require_login():
    """Gate the app behind a login form when auth is configured.

    No-op (returns immediately) when NIDS_AUTH_PASSWORD_HASH is unset, so the
    app stays open by default. When configured, an unauthenticated session
    sees only the login form and the rest of the script is halted via
    st.stop().
    """
    if not auth.is_auth_configured():
        return
    if st.session_state.get("authenticated"):
        return

    if _logo_b64:
        st.markdown(
            f'<div style="text-align:center"><img src="data:image/svg+xml;base64,{_logo_b64}" width="80" alt="NIDS logo"/></div>',
            unsafe_allow_html=True,
        )
    st.markdown("<h3 style='text-align:center'>🔒 NIDS — Sign in</h3>", unsafe_allow_html=True)

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in")

    if submitted:
        role = auth.authenticate(username, password)
        if role is not None:
            st.session_state["authenticated"] = True
            st.session_state["user_role"] = role
            st.session_state["user_name"] = username
            st.rerun()
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


header_logo, header_text = st.columns([1, 11], vertical_alignment="center")
with header_logo:
    if _logo_b64:
        st.markdown(
            f'<img src="data:image/svg+xml;base64,{_logo_b64}" width="64" alt="NIDS logo"/>',
            unsafe_allow_html=True,
        )
with header_text:
    st.title("AI Network Intrusion Detection System")
    st.caption("Random Forest, Decision Tree and Isolation Forest — compared side by side on the same traffic.")

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
            st.error("❌ Critical Error: Could not find 'KDDTrain+.txt'")
            st.stop()
        train_df = pd.read_csv(train_path, names=columns)

        encoders = {}
        categorical_cols = ['protocol_type', 'service', 'flag']
        for col in categorical_cols:
            le = LabelEncoder()
            le.fit(train_df[col])
            encoders[col] = le

        test_path = get_data_path('KDDTest+.txt')
        rf_acc, dt_acc, iforest_acc = 0.0, 0.0, 0.0
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
            f"❌ Missing file: {e}\n\n"
            "Models live in `models/` and the dataset in `data/nsl-kdd/`. "
            "Run `python scripts/train_models.py` to regenerate the models."
        )
        st.stop()
    except Exception as e:
        # A corrupt or version-mismatched .pkl used to escape as a raw
        # traceback; joblib models are tied to the scikit-learn version they
        # were trained with.
        st.error(
            f"❌ Could not load the models: {type(e).__name__}: {e}\n\n"
            "This usually means the `.pkl` files were trained with a different "
            "scikit-learn version. Re-run `python scripts/train_models.py`."
        )
        st.stop()

rf_model, dt_model, iforest_model, encoders, rf_acc, dt_acc, iforest_acc = load_resources()

# Sidebar branding
if _logo_b64:
    st.sidebar.markdown(
        f'<div style="text-align:center"><img src="data:image/svg+xml;base64,{_logo_b64}" width="56" alt="NIDS logo"/></div>',
        unsafe_allow_html=True,
    )
    st.sidebar.markdown(
        f'<p style="text-align:center; opacity:0.7; margin-top:-8px;">NIDS v{NIDS_VERSION}</p>',
        unsafe_allow_html=True,
    )

# Logout (only shown when auth is active and the user is signed in).
if auth.is_auth_configured() and st.session_state.get("authenticated"):
    signed_in = st.session_state.get("user_name", auth.configured_username())
    role_label = st.session_state.get("user_role", "")
    st.sidebar.caption(f"Signed in as **{signed_in}** ({role_label})")
    if st.sidebar.button("🔓 Log out"):
        for k in ("authenticated", "user_role", "user_name"):
            st.session_state.pop(k, None)
        st.rerun()

# Sidebar Metrics.
# Rendered as real metrics rather than st.info/st.warning/st.success boxes:
# a yellow "warning" box for a healthy Decision Tree score read as an alarm,
# and those box colours contradicted each model's colour in the charts.
st.sidebar.header("📊 Model accuracy")
st.sidebar.caption("Measured on the NSL-KDD test set.")
acc_left, acc_right = st.sidebar.columns(2)
acc_left.metric("🌲 Random Forest", f"{rf_acc*100:.1f}%")
acc_right.metric("🌳 Decision Tree", f"{dt_acc*100:.1f}%")
if iforest_model is not None:
    st.sidebar.metric("🧭 Isolation Forest", f"{iforest_acc*100:.1f}%")
else:
    st.sidebar.caption("🧭 Isolation Forest not found — run `python scripts/train_models.py` to enable it.")

st.sidebar.header("⚙️ Thresholds")
critical_threshold_pct = st.sidebar.slider(
    "🚨 CRITICAL threshold (% flagged as attack)",
    min_value=5, max_value=100, value=DEFAULT_CRITICAL_THRESHOLD_PCT, step=5,
    help="Traffic at or above this percentage is flagged CRITICAL. Anything "
         "above 0% and below this is SUSPICIOUS.",
)

st.sidebar.header("🔔 Notifications")
enable_sound_alert = st.sidebar.checkbox("Play a sound on critical threat", value=False)
enable_browser_notification = st.sidebar.checkbox(
    "Show a browser notification on critical threat", value=False,
    help="Your browser will ask for notification permission the first time.",
)

with st.sidebar.expander("ℹ️ About this project"):
    st.markdown(
        f"""
        **NIDS v{NIDS_VERSION}** compares Random Forest, Decision Tree, and
        (optionally) Isolation Forest classifiers trained on the NSL-KDD
        dataset, on the same live or uploaded traffic — side by side.

        - Dataset source & citation: `docs/DATASET.md`
        - Architecture notes: `docs/architecture/architecture.md`
        - Found a bug? Use the templates under `.github/ISSUE_TEMPLATE/`.
        """
    )

def render_block_suggestions(ip):
    """Show copy-paste firewall block rules for a flagged IP (suggestion only).

    Renders nothing for IPs that shouldn't be blocked (loopback/invalid).
    These commands are never executed by the app — the operator reviews and
    applies them manually.
    """
    rules = firewall.block_rule_snippets(ip)
    if not rules:
        return
    with st.expander(f"🚫 Suggested block rules for {ip}"):
        st.caption("Review before applying — NIDS never runs these for you.")
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

    attacks = df[df[col_name] == '🚨 ATTACK']
    attack_count = len(attacks)
    attack_pct = (attack_count / total) * 100

    st.markdown(f"##### 🤖 {model_name} Assessment")

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
            st.toast(f"CRITICAL THREAT — {model_name} flagged {attack_pct:.1f}% of traffic", icon="🚨")
            sent_channels = alerts.send_critical_alert(model_name, attack_pct, top_attacker, top_victim)
            if sent_channels:
                st.caption(f"🔔 Alert sent via: {', '.join(sent_channels)}")

            # Client-side sound / browser notification (opt-in via sidebar).
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
    df_display['RF Analysis'] = ['🚨 ATTACK' if p == 1 else '✅ Normal' for p in rf_pred]
    df_display['DT Analysis'] = ['🚨 ATTACK' if p == 1 else '✅ Normal' for p in dt_pred]

    if iforest_model is not None:
        iforest_pred = iforest_model.predict(X_processed)
        df_display['Anomaly Analysis'] = anomaly.to_verdict(iforest_pred)

    return df_display


MODEL_COLUMN_STYLE = {
    'RF Analysis': {'label': '🌲 Random Forest', 'color': COLOR_RF,
                    'hint': 'Supervised — trained on labelled NSL-KDD attacks.'},
    'DT Analysis': {'label': '🌳 Decision Tree', 'color': COLOR_DT,
                    'hint': 'Supervised — a single interpretable tree.'},
    'Anomaly Analysis': {'label': '🧭 Isolation Forest', 'color': COLOR_IFOREST,
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
        y=alt.Y('src_bytes', scale=alt.Scale(type='symlog'), title='Packet size (bytes, log)'),
        color=alt.Color(verdict_col, scale=VERDICT_SCALE, legend=None),
    ).properties(height=200, title="Packet size by verdict")
    st.altair_chart(box_chart, width='stretch')

    # 4. SCATTER PLOT (Log-Log)
    scatter_chart = alt.Chart(df_display).mark_circle(size=100).encode(
        x=alt.X('src_bytes', scale=alt.Scale(type='symlog'), title='Packet size (bytes, log)'),
        y=alt.Y('count', scale=alt.Scale(type='symlog'), title='Traffic count (log)'),
        color=alt.Color(verdict_col, scale=VERDICT_SCALE, legend=None),
        tooltip=['src_ip', 'src_bytes', 'count', verdict_col]
    ).properties(height=300, title="Volume vs size").interactive()
    st.altair_chart(scatter_chart, width='stretch')

    # 5. AI SUMMARY
    generate_smart_summary(df_display, verdict_col, model_name, critical_threshold_pct)


def display_results(df, key_suffix="", allow_download=True):
    st.divider()
    try:
        df_display = classify(df)

        if allow_download:
            dl_csv, dl_pdf = st.columns(2)
            with dl_csv:
                csv = df_display.to_csv(index=False).encode('utf-8')
                # Explicit keys: this renders in more than one tab, and
                # identical auto-generated widget IDs would collide.
                st.download_button(
                    "⬇️ Download CSV", csv, f"report_{key_suffix}.csv", "text/csv",
                    key=f"dl_csv_{key_suffix}", width='stretch',
                )
            with dl_pdf:
                pdf_bytes = reporting.build_report_pdf(df_display)
                if pdf_bytes is not None:
                    st.download_button(
                        "📄 Download PDF report", pdf_bytes,
                        f"report_{key_suffix}.pdf", "application/pdf",
                        key=f"dl_pdf_{key_suffix}", width='stretch',
                    )
                else:
                    st.caption("PDF export needs `reportlab`.")

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
        st.error(f"❌ Could not analyse this traffic: {type(e).__name__}: {e}")
        with st.expander("Technical details"):
            st.code(traceback.format_exc(), language="text")

# --- 7. UI Layout ---
tab1, tab2, tab3, tab4 = st.tabs(
    ["📡 Live Capture", "📂 Upload Wireshark File", "🧠 Model Logic", "📜 History"]
)

# === TAB 1: Live Capture ===
with tab1:
    st.subheader("Live Network Sniffer")

    capture_ready, capture_message = netcheck.capture_readiness()
    if not capture_ready:
        st.warning(f"⚠️ {capture_message}")
    else:
        st.caption(f"ℹ️ {netcheck.privilege_hint()}")

    c1, c2 = st.columns([1, 4])
    with c1:
        start = st.button(
            "▶️ Start Capture", disabled=not capture_ready or st.session_state.get("is_running", False)
        )
        stop = st.button("⏹️ Stop Capture", disabled=not st.session_state.get("is_running", False))
    status_placeholder = c2.empty()

    throughput_placeholder = st.empty()
    live_placeholder = st.empty()

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

    if start:
        st.session_state.is_running = True
    if stop:
        st.session_state.is_running = False

    def render_throughput():
        agg = throughput.aggregate_per_second(st.session_state.throughput_samples)
        if len(agg) < 2:
            return
        # Plot seconds-ago rather than the raw epoch second: an axis reading
        # "1721208000" is meaningless to a human watching live traffic.
        agg = agg.copy()
        agg["ago"] = agg["second"] - agg["second"].max()
        agg_long = agg.melt(
            id_vars=["ago"], value_vars=["packets", "kbytes"],
            var_name="Metric", value_name="Rate",
        )
        agg_long["Metric"] = agg_long["Metric"].map(
            {"packets": "Packets/sec", "kbytes": "KB/sec"}
        )
        chart = alt.Chart(agg_long).mark_area(opacity=0.5).encode(
            x=alt.X("ago:Q", title="Seconds ago", scale=alt.Scale(domain=[-60, 0])),
            y=alt.Y("Rate:Q", title="Rate"),
            color=alt.Color(
                "Metric:N", title=None,
                scale=alt.Scale(domain=["Packets/sec", "KB/sec"], range=[COLOR_NORMAL, COLOR_IFOREST]),
            ),
            tooltip=[alt.Tooltip("ago:Q", title="Seconds ago"), "Metric:N", alt.Tooltip("Rate:Q", format=".1f")],
        ).properties(height=180, title="📶 Live throughput (last 60s)")
        throughput_placeholder.altair_chart(chart, width='stretch')

    if st.session_state.is_running:
        # Capture ONE batch per script run, then st.rerun() to come back for
        # the next one. A blocking `while` loop here would never return control
        # to Streamlit, and since a button click is only processed on a fresh
        # script run, "⏹️ Stop Capture" could never fire — the capture would be
        # unstoppable. Rerunning between batches keeps the UI responsive.
        st.info("🔴 **Capturing…** press ⏹️ Stop Capture to pause.")

        pkt_batch = sniff(count=LIVE_BATCH_SIZE, timeout=LIVE_SNIFF_TIMEOUT)

        if pkt_batch:
            # Keep enough raw packets around (not just derived rows) so
            # packets_to_df can recompute proper windowed stats
            # (count/srv_count/*_rate) instead of a single-packet snapshot.
            st.session_state.raw_packets.extend(pkt_batch)
            st.session_state.raw_packets = st.session_state.raw_packets[-RAW_PACKET_BUFFER:]
            st.session_state.total_captured += len(pkt_batch)

            # Record a throughput sample for this second.
            now_sec = int(time.time())
            batch_bytes = sum(len(p) for p in pkt_batch)
            st.session_state.throughput_samples.append(
                {"t": now_sec, "packets": len(pkt_batch), "bytes": batch_bytes}
            )
            st.session_state.throughput_samples = throughput.trim_samples(
                st.session_state.throughput_samples, max_seconds=60, now=now_sec
            )

            windowed_df = packets_to_df(st.session_state.raw_packets)
            st.session_state.continuous_df = windowed_df.tail(100)

            if not st.session_state.continuous_df.empty:
                # Persist only this batch's newest rows, not the whole rolling
                # 100-row display window (which would re-insert already-saved
                # rows into history on every batch).
                new_rows = windowed_df.tail(len(pkt_batch))
                storage.save_detections(classify(new_rows), source="live")

        status_placeholder.metric("📈 Packets captured (this session)", st.session_state.total_captured)
        render_throughput()

        if not st.session_state.continuous_df.empty:
            with live_placeholder.container():
                display_results(st.session_state.continuous_df, "continuous", allow_download=False)
        else:
            live_placeholder.caption("Waiting for the first packets…")

        st.rerun()

    elif not st.session_state.continuous_df.empty:
        status_placeholder.metric("📈 Packets captured (this session)", st.session_state.total_captured)
        render_throughput()
        with live_placeholder.container():
            st.info("⏸️ Capture paused — showing the last captured window.")
            display_results(st.session_state.continuous_df, "continuous", allow_download=True)
    elif capture_ready:
        live_placeholder.caption("Press ▶️ Start Capture to begin monitoring live traffic.")

# === TAB 2: File Upload (Auto-Clean Logic Added) ===
with tab2:
    st.subheader("Analyze .pcap Files")
    st.caption(
        "Upload a Wireshark capture to classify it with all models. "
        "No sample handy? Try the ones in `data/pcaps/` "
        "(`ddos_attack.pcap`, `neptune_attack.pcap`, `mixed_attack.pcap`)."
    )
    uploaded_file = st.file_uploader("Upload .pcap", type=["pcap", "pcapng"], key="file_uploader")

    # CLEANUP: If file is removed, clear session state and reload
    if uploaded_file is None:
        if 'upload_data' in st.session_state:
            del st.session_state['upload_data']
            if 'last_file' in st.session_state:
                del st.session_state['last_file']
            st.rerun()

    # PROCESS: If file exists, process it
    if uploaded_file is not None:
        if st.session_state.get('last_file') != uploaded_file.name:
            with st.spinner("Processing..."):
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                    tmp.write(uploaded_file.getvalue())
                    tmp_name = tmp.name
                try:
                    packets = rdpcap(tmp_name)
                    upload_df = packets_to_df(packets)
                    st.session_state['upload_data'] = upload_df
                    st.session_state['last_file'] = uploaded_file.name

                    # Persist exactly once per uploaded file (this block only
                    # runs when the filename changes), not on every rerun.
                    if not upload_df.empty:
                        storage.save_detections(classify(upload_df), source="upload")
                finally:
                    os.remove(tmp_name)

    # DISPLAY: Show results if data exists
    if 'upload_data' in st.session_state:
        display_results(st.session_state['upload_data'], "upload", allow_download=True)

# === TAB 3: Explainable AI ===
with tab3:
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
                    f"<strong>🌲 Random Forest</strong></div>", unsafe_allow_html=True)
        st.altair_chart(_importance_chart(rf_model, COLOR_RF), width='stretch')
    with col2:
        st.markdown(f"<div style='border-left:4px solid {COLOR_DT};padding:2px 0 2px 10px;'>"
                    f"<strong>🌳 Decision Tree</strong></div>", unsafe_allow_html=True)
        st.altair_chart(_importance_chart(dt_model, COLOR_DT), width='stretch')

    # Previously this tab silently showed only RF/DT, leaving users to wonder
    # where the third model went.
    if iforest_model is not None:
        st.info(
            "🧭 **Isolation Forest** isn't shown here: it's unsupervised and "
            "scores how *isolated* a connection is rather than learning "
            "per-feature attack importances, so scikit-learn exposes no "
            "`feature_importances_` for it."
        )

# === TAB 4: History (persisted beyond the in-memory 100-row buffer) ===
with tab4:
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

        m1, m2, m3 = st.columns(3)
        m1.metric("Total detections", total)
        m2.metric("RF attacks flagged", rf_attacks, f"{rf_attacks / total * 100:.1f}%")
        m3.metric("DT attacks flagged", dt_attacks, f"{dt_attacks / total * 100:.1f}%")

        st.markdown("##### Attacks over time")
        trend_df = storage.query_trend()
        if len(trend_df) >= 2:
            trend_long = trend_df.melt(
                id_vars=["bucket"], value_vars=["rf_attacks", "dt_attacks"],
                var_name="Model", value_name="Attacks",
            )
            trend_long["Model"] = trend_long["Model"].map(
                {"rf_attacks": "Random Forest", "dt_attacks": "Decision Tree"}
            )
            # Real temporal axis: a nominal ("bucket:N") axis rendered one
            # crowded tick per minute and became unreadable as history grew.
            trend_long["bucket"] = pd.to_datetime(trend_long["bucket"], utc=True, errors="coerce")
            trend_chart = alt.Chart(trend_long.dropna(subset=["bucket"])).mark_line(point=True).encode(
                x=alt.X("bucket:T", title="Time (UTC)"),
                y=alt.Y("Attacks:Q", title="Attacks flagged"),
                color=alt.Color(
                    "Model:N", title=None,
                    scale=alt.Scale(domain=["Random Forest", "Decision Tree"], range=[COLOR_RF, COLOR_DT]),
                ),
                tooltip=[alt.Tooltip("bucket:T", title="Time"), "Model:N", "Attacks:Q"],
            ).properties(height=250)
            st.altair_chart(trend_chart, width='stretch')
        else:
            st.caption("Trend chart needs at least 2 minutes of history — capture more traffic to see it.")

        st.markdown("##### Export full history")
        if not is_admin_user():
            st.caption("🔒 Export is available to admin users only.")
        else:
            st.caption(f"Download all {total} persisted detections (not just the view below).")
            all_history = storage.query_all()
            exp_csv, exp_xlsx, exp_enc = st.columns(3)
            with exp_csv:
                st.download_button(
                    "⬇️ CSV (all history)",
                    all_history.to_csv(index=False).encode("utf-8"),
                    "nids_history.csv",
                    "text/csv",
                    width='stretch',
                )
            with exp_xlsx:
                xlsx_bytes = _dataframe_to_excel_bytes(all_history)
                if xlsx_bytes is not None:
                    st.download_button(
                        "⬇️ Excel (all history)",
                        xlsx_bytes,
                        "nids_history.xlsx",
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        width='stretch',
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
                            "🔐 Encrypted backup",
                            enc_bytes,
                            "nids_history.db.enc",
                            "application/octet-stream",
                            width='stretch',
                        )

        st.divider()
        st.markdown("##### 🌍 Source IP geography")
        distinct_ips = storage.query_distinct_ips()
        category_counts = geo.categorize_ips(distinct_ips)
        if category_counts:
            cat_df = pd.DataFrame(
                {"Category": list(category_counts.keys()), "IPs": list(category_counts.values())}
            )
            cat_chart = alt.Chart(cat_df).mark_bar().encode(
                x=alt.X("IPs:Q"),
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
        st.markdown("##### 🔎 Drill down by source IP")
        ip_options = ["(select an IP)"] + distinct_ips
        selected_ip = st.selectbox(
            "Source IP", ip_options,
            help="See every past detection for one source IP across all sessions.",
        )
        if selected_ip != "(select an IP)":
            ip_summary = storage.query_ip_summary(selected_ip)
            ip_total = int(ip_summary["total"] or 0)
            ip_rf = int(ip_summary["rf_attacks"] or 0)
            ip_dt = int(ip_summary["dt_attacks"] or 0)

            d1, d2, d3 = st.columns(3)
            d1.metric("Detections", ip_total)
            d2.metric("RF attacks", ip_rf, f"{(ip_rf / ip_total * 100) if ip_total else 0:.1f}%")
            d3.metric("DT attacks", ip_dt, f"{(ip_dt / ip_total * 100) if ip_total else 0:.1f}%")
            st.caption(f"First seen: {ip_summary['first_seen']} · Last seen: {ip_summary['last_seen']} (UTC)")
            render_block_suggestions(selected_ip)
            st.dataframe(storage.query_by_ip(selected_ip), width='stretch')

        st.divider()
        st.markdown("##### Most recent 200 detections")
        sources = ["All"] + storage.query_sources()
        selected_source = st.selectbox("Filter by source", sources)
        source_filter = None if selected_source == "All" else selected_source
        st.dataframe(storage.query_recent(limit=200, source=source_filter), width='stretch')
