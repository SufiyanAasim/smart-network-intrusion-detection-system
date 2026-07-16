import base64
import os
import sys

# Make the `nids` package importable when this file is launched directly via
# `streamlit run src/nids/app.py` (Streamlit runs it as a standalone script,
# so `src/` needs to be on sys.path for `from nids.features import ...`).
_SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

_BASE_DIR = os.path.dirname(_SRC_DIR)
_LOGO_PATH = os.path.join(_BASE_DIR, "assets", "images", "logo.svg")

import streamlit as st  # noqa: E402
import pandas as pd  # noqa: E402
import joblib  # noqa: E402
from scapy.all import sniff, rdpcap  # noqa: E402
from sklearn.preprocessing import LabelEncoder  # noqa: E402
from sklearn.metrics import accuracy_score  # noqa: E402
import tempfile  # noqa: E402
import altair as alt  # noqa: E402
import time  # noqa: E402

from nids.features import MODEL_FEATURES, WINDOW_CONNECTIONS, preprocess_data, packets_to_df  # noqa: E402
from nids import storage, alerts, anomaly  # noqa: E402
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

header_logo, header_text = st.columns([1, 9])
with header_logo:
    if _logo_b64:
        st.markdown(
            f'<img src="data:image/svg+xml;base64,{_logo_b64}" width="72" alt="NIDS logo"/>',
            unsafe_allow_html=True,
        )
with header_text:
    st.title("AI Network Intrusion Detection System")
    st.markdown("Compare **Random Forest**, **Decision Tree**, and **Isolation Forest** models side-by-side.")

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
        st.error(f"❌ File Not Found Error: {e}")
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

# Sidebar Metrics
st.sidebar.header("📊 Model Accuracy")
st.sidebar.info(f"**🌲 RF**: {rf_acc*100:.2f}%")
st.sidebar.warning(f"**🌳 DT**: {dt_acc*100:.2f}%")
if iforest_model is not None:
    st.sidebar.success(f"**🧭 Isolation Forest**: {iforest_acc*100:.2f}%")
else:
    st.sidebar.caption("Isolation Forest model not found — run `python scripts/train_models.py` to enable it.")

st.sidebar.header("⚙️ Thresholds")
critical_threshold_pct = st.sidebar.slider(
    "🚨 CRITICAL threshold (% flagged as attack)",
    min_value=5, max_value=100, value=DEFAULT_CRITICAL_THRESHOLD_PCT, step=5,
    help="Traffic at or above this percentage is flagged CRITICAL. Anything "
         "above 0% and below this is SUSPICIOUS.",
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

        cooldown_key = f"last_alert_{model_name}"
        last_alert_at = st.session_state.get(cooldown_key, 0.0)
        if time.time() - last_alert_at >= ALERT_COOLDOWN_SECONDS:
            st.session_state[cooldown_key] = time.time()
            st.toast(f"CRITICAL THREAT — {model_name} flagged {attack_pct:.1f}% of traffic", icon="🚨")
            sent_channels = alerts.send_critical_alert(model_name, attack_pct, top_attacker, top_victim)
            if sent_channels:
                st.caption(f"🔔 Alert sent via: {', '.join(sent_channels)}")

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
    'RF Analysis': {'label': '🌲 Random Forest', 'banner': 'info'},
    'DT Analysis': {'label': '🌳 Decision Tree', 'banner': 'warning'},
    'Anomaly Analysis': {'label': '🧭 Isolation Forest (Anomaly)', 'banner': 'success'},
}


def render_model_column(df_display, verdict_col, model_name, common_cols):
    style = MODEL_COLUMN_STYLE[verdict_col]
    getattr(st, style['banner'])(style['label'])

    # 1. TABLE
    st.dataframe(df_display[common_cols + [verdict_col]], use_container_width=True)
    st.markdown("---")

    # 2. BAR CHART
    counts = df_display[verdict_col].value_counts().reset_index()
    counts.columns = ['Status', 'Count']
    chart = alt.Chart(counts).mark_bar().encode(
        x='Status', y='Count', color=alt.Color('Status', scale=alt.Scale(domain=['✅ Normal', '🚨 ATTACK'], range=['#00CC96', '#EF553B']))
    ).properties(height=200, title="Threat Distribution")
    st.altair_chart(chart, use_container_width=True)

    # 3. BOX PLOT (Log)
    box_chart = alt.Chart(df_display).mark_boxplot().encode(
        x=verdict_col,
        y=alt.Y('src_bytes', scale=alt.Scale(type='symlog')),
        color=verdict_col,
    ).properties(height=200, title="Packet Size (Log)")
    st.altair_chart(box_chart, use_container_width=True)

    # 4. SCATTER PLOT (Log-Log)
    scatter_chart = alt.Chart(df_display).mark_circle(size=100).encode(
        x=alt.X('src_bytes', scale=alt.Scale(type='symlog'), title='Packet Size (Bytes)'),
        y=alt.Y('count', scale=alt.Scale(type='symlog'), title='Traffic Count'),
        color=alt.Color(verdict_col, scale=alt.Scale(domain=['✅ Normal', '🚨 ATTACK'], range=['#00CC96', '#EF553B'])),
        tooltip=['src_ip', 'src_bytes', 'count', verdict_col]
    ).properties(height=300, title="Volume vs Size").interactive()
    st.altair_chart(scatter_chart, use_container_width=True)

    # 5. AI SUMMARY
    generate_smart_summary(df_display, verdict_col, model_name, critical_threshold_pct)


def display_results(df, key_suffix="", allow_download=True):
    st.divider()
    try:
        df_display = classify(df)

        if allow_download:
            csv = df_display.to_csv(index=False).encode('utf-8')
            st.download_button("⬇️ Download CSV", csv, f"report_{key_suffix}.csv", "text/csv")

        common_cols = ['src_ip', 'flag', 'count', 'serror_rate', 'src_bytes']
        model_columns = [('RF Analysis', 'Random Forest'), ('DT Analysis', 'Decision Tree')]
        if 'Anomaly Analysis' in df_display.columns:
            model_columns.append(('Anomaly Analysis', 'Isolation Forest'))

        for col, (verdict_col, model_name) in zip(st.columns(len(model_columns)), model_columns):
            with col:
                render_model_column(df_display, verdict_col, model_name, common_cols)

    except Exception as e:
        st.error(f"Error: {e}")

# --- 7. UI Layout ---
tab1, tab2, tab3, tab4 = st.tabs(
    ["📡 Live Capture", "📂 Upload Wireshark File", "🧠 Model Logic", "📜 History"]
)

# === TAB 1: Live Capture ===
with tab1:
    st.subheader("Live Network Sniffer")

    c1, c2 = st.columns([1, 4])
    with c1:
        start = st.button("▶️ Start Capture")
        stop = st.button("⏹️ Stop Capture")
    status_placeholder = c2.empty()

    live_placeholder = st.empty()

    if 'raw_packets' not in st.session_state:
        st.session_state.raw_packets = []

    if 'continuous_df' not in st.session_state:
        st.session_state.continuous_df = pd.DataFrame()

    if 'is_running' not in st.session_state:
        st.session_state.is_running = False

    if 'total_captured' not in st.session_state:
        st.session_state.total_captured = 0

    if start:
        st.session_state.is_running = True
    if stop:
        st.session_state.is_running = False

    if st.session_state.is_running:
        with st.spinner("Monitoring Network..."):
            while st.session_state.is_running:
                pkt_batch = sniff(count=1, timeout=1)

                if pkt_batch:
                    # Keep enough raw packets around (not just derived rows) so
                    # packets_to_df can recompute proper windowed stats
                    # (count/srv_count/*_rate) instead of a single-packet snapshot.
                    st.session_state.raw_packets.extend(pkt_batch)
                    st.session_state.raw_packets = st.session_state.raw_packets[-RAW_PACKET_BUFFER:]
                    st.session_state.total_captured += len(pkt_batch)
                    status_placeholder.metric("📈 Packets captured (this session)", st.session_state.total_captured)

                    windowed_df = packets_to_df(st.session_state.raw_packets)
                    st.session_state.continuous_df = windowed_df.tail(100)

                    if not st.session_state.continuous_df.empty:
                        # Persist only this tick's newest rows, not the whole
                        # rolling 100-row display window (which would
                        # re-insert already-saved rows into history on every
                        # ~0.1s tick).
                        new_rows = windowed_df.tail(len(pkt_batch))
                        storage.save_detections(classify(new_rows), source="live")

                        with live_placeholder.container():
                            display_results(st.session_state.continuous_df, "continuous", allow_download=False)

                time.sleep(0.1)

    elif not st.session_state.continuous_df.empty:
        status_placeholder.metric("📈 Packets captured (this session)", st.session_state.total_captured)
        with live_placeholder.container():
            st.info("Capture Paused.")
            display_results(st.session_state.continuous_df, "continuous", allow_download=True)

# === TAB 2: File Upload (Auto-Clean Logic Added) ===
with tab2:
    st.subheader("Analyze .pcap Files")
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
    col1, col2 = st.columns(2)
    with col1:
        st.info("Random Forest Features")
        imp = pd.DataFrame({'Feature': MODEL_FEATURES, 'Importance': rf_model.feature_importances_}).sort_values('Importance', ascending=False).head(10)
        st.altair_chart(alt.Chart(imp).mark_bar().encode(x='Importance', y=alt.Y('Feature', sort='-x'), color=alt.value('#00CC96')), use_container_width=True)
    with col2:
        st.warning("Decision Tree Features")
        imp = pd.DataFrame({'Feature': MODEL_FEATURES, 'Importance': dt_model.feature_importances_}).sort_values('Importance', ascending=False).head(10)
        st.altair_chart(alt.Chart(imp).mark_bar().encode(x='Importance', y=alt.Y('Feature', sort='-x'), color=alt.value('#FFB84C')), use_container_width=True)

# === TAB 4: History (persisted beyond the in-memory 100-row buffer) ===
with tab4:
    st.subheader("Detection History")
    st.caption(f"Persisted to `{os.path.relpath(storage.DEFAULT_DB_PATH, BASE_DIR)}`")

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
            trend_chart = alt.Chart(trend_long).mark_line(point=True).encode(
                x=alt.X("bucket:N", title="Time (UTC, per-minute)"),
                y=alt.Y("Attacks:Q"),
                color=alt.Color(
                    "Model:N",
                    scale=alt.Scale(domain=["Random Forest", "Decision Tree"], range=["#00CC96", "#FFB84C"]),
                ),
                tooltip=["bucket", "Model", "Attacks"],
            ).properties(height=250)
            st.altair_chart(trend_chart, use_container_width=True)
        else:
            st.caption("Trend chart needs at least 2 minutes of history — capture more traffic to see it.")

        st.markdown("##### Most recent 200 detections")
        sources = ["All"] + storage.query_sources()
        selected_source = st.selectbox("Filter by source", sources)
        source_filter = None if selected_source == "All" else selected_source
        st.dataframe(storage.query_recent(limit=200, source=source_filter), use_container_width=True)
