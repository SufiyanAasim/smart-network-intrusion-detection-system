import os
import sys

# Make the `nids` package importable when this file is launched directly via
# `streamlit run src/nids/app.py` (Streamlit runs it as a standalone script,
# so `src/` needs to be on sys.path for `from nids.features import ...`).
_SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

import streamlit as st
import pandas as pd
import joblib
from scapy.all import sniff, rdpcap
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score
import tempfile
import altair as alt
import time

from nids.features import MODEL_FEATURES, preprocess_data, packets_to_df

# --- 1. Page Configuration ---
st.set_page_config(page_title="Network Intrusion Detection", layout="wide")

st.title("🛡️ AI Network Intrusion Detection System")
st.markdown("Compare **Random Forest** and **Decision Tree** models side-by-side.")

# --- 2. Smart Path Finding ---
BASE_DIR = os.path.dirname(_SRC_DIR)
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

        columns = MODEL_FEATURES + ['label', 'difficulty_level']

        train_path = get_data_path('KDDTrain+.txt')
        if not os.path.exists(train_path):
            st.error(f"❌ Critical Error: Could not find 'KDDTrain+.txt'")
            st.stop()
        train_df = pd.read_csv(train_path, names=columns)

        encoders = {}
        categorical_cols = ['protocol_type', 'service', 'flag']
        for col in categorical_cols:
            le = LabelEncoder()
            le.fit(train_df[col])
            encoders[col] = le

        test_path = get_data_path('KDDTest+.txt')
        rf_acc, dt_acc = 0.0, 0.0
        if os.path.exists(test_path):
            test_df = pd.read_csv(test_path, names=columns)
            X_test = test_df[MODEL_FEATURES].copy()
            y_test = test_df['label'].apply(lambda x: 0 if x == 'normal' else 1)
            X_test_encoded = preprocess_data(X_test, encoders)
            rf_acc = accuracy_score(y_test, rf_model.predict(X_test_encoded))
            dt_acc = accuracy_score(y_test, dt_model.predict(X_test_encoded))
            
        return rf_model, dt_model, encoders, rf_acc, dt_acc
        
    except FileNotFoundError as e:
        st.error(f"❌ File Not Found Error: {e}")
        st.stop()

rf_model, dt_model, encoders, rf_acc, dt_acc = load_resources()

# Sidebar Metrics
st.sidebar.header("📊 Model Accuracy")
st.sidebar.info(f"**🌲 RF**: {rf_acc*100:.2f}%")
st.sidebar.warning(f"**🌳 DT**: {dt_acc*100:.2f}%")

# --- 5. AI Summary Generator ---
def generate_smart_summary(df, col_name, model_name):
    """
    Acts as a simulated AI analyst.
    Calculates stats and generates a text summary based on logic.
    """
    total = len(df)
    if total == 0: return
    
    attacks = df[df[col_name] == '🚨 ATTACK']
    attack_count = len(attacks)
    attack_pct = (attack_count / total) * 100
    
    st.markdown(f"##### 🤖 {model_name} Assessment")
    
    if attack_pct == 0:
        st.success(f"**Status: SAFE.** No malicious traffic detected in the last {total} packets. Network behavior appears normal.")
    elif attack_pct < 20:
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

def display_results(df, key_suffix="", allow_download=True):
    st.divider()
    try:
        X_clean = df[MODEL_FEATURES].copy()
        X_processed = preprocess_data(X_clean, encoders)
        
        rf_pred = rf_model.predict(X_processed)
        dt_pred = dt_model.predict(X_processed)
        
        df_display = df.copy()
        df_display['RF Analysis'] = ['🚨 ATTACK' if p==1 else '✅ Normal' for p in rf_pred]
        df_display['DT Analysis'] = ['🚨 ATTACK' if p==1 else '✅ Normal' for p in dt_pred]
        
        if allow_download:
            csv = df_display.to_csv(index=False).encode('utf-8')
            st.download_button("⬇️ Download CSV", csv, f"report_{key_suffix}.csv", "text/csv")

        col1, col2 = st.columns(2)
        common_cols = ['src_ip', 'flag', 'count', 'serror_rate', 'src_bytes']
        
        # --- LEFT COLUMN: Random Forest ---
        with col1:
            st.info("🌲 Random Forest")
            
            # 1. TABLE
            st.dataframe(df_display[common_cols + ['RF Analysis']], use_container_width=True)
            st.markdown("---")
            
            # 2. BAR CHART
            rf_counts = df_display['RF Analysis'].value_counts().reset_index()
            rf_counts.columns = ['Status', 'Count']
            chart = alt.Chart(rf_counts).mark_bar().encode(
                x='Status', y='Count', color=alt.Color('Status', scale=alt.Scale(domain=['✅ Normal', '🚨 ATTACK'], range=['#00CC96', '#EF553B']))
            ).properties(height=200, title="Threat Distribution")
            st.altair_chart(chart, use_container_width=True)
            
            # 3. BOX PLOT (Log)
            box_chart = alt.Chart(df_display).mark_boxplot().encode(
                x='RF Analysis',
                y=alt.Y('src_bytes', scale=alt.Scale(type='symlog')), 
                color='RF Analysis'
            ).properties(height=200, title="Packet Size (Log)")
            st.altair_chart(box_chart, use_container_width=True)
            
            # 4. SCATTER PLOT (Log-Log)
            scatter_chart = alt.Chart(df_display).mark_circle(size=100).encode(
                x=alt.X('src_bytes', scale=alt.Scale(type='symlog'), title='Packet Size (Bytes)'),
                y=alt.Y('count', scale=alt.Scale(type='symlog'), title='Traffic Count'),
                color=alt.Color('RF Analysis', scale=alt.Scale(domain=['✅ Normal', '🚨 ATTACK'], range=['#00CC96', '#EF553B'])),
                tooltip=['src_ip', 'src_bytes', 'count', 'RF Analysis']
            ).properties(height=300, title="Volume vs Size").interactive()
            st.altair_chart(scatter_chart, use_container_width=True)
            
            # 5. AI SUMMARY
            generate_smart_summary(df_display, 'RF Analysis', 'Random Forest')

        # --- RIGHT COLUMN: Decision Tree ---
        with col2:
            st.warning("🌳 Decision Tree")
            
            # 1. TABLE
            st.dataframe(df_display[common_cols + ['DT Analysis']], use_container_width=True)
            st.markdown("---")
            
            # 2. BAR CHART
            dt_counts = df_display['DT Analysis'].value_counts().reset_index()
            dt_counts.columns = ['Status', 'Count']
            chart = alt.Chart(dt_counts).mark_bar().encode(
                x='Status', y='Count', color=alt.Color('Status', scale=alt.Scale(domain=['✅ Normal', '🚨 ATTACK'], range=['#00CC96', '#EF553B']))
            ).properties(height=200, title="Threat Distribution")
            st.altair_chart(chart, use_container_width=True)
            
            # 3. BOX PLOT (Log)
            box_chart = alt.Chart(df_display).mark_boxplot().encode(
                x='DT Analysis',
                y=alt.Y('src_bytes', scale=alt.Scale(type='symlog')), 
                color='DT Analysis'
            ).properties(height=200, title="Packet Size (Log)")
            st.altair_chart(box_chart, use_container_width=True)

            # 4. SCATTER PLOT (Log-Log)
            scatter_chart = alt.Chart(df_display).mark_circle(size=100).encode(
                x=alt.X('src_bytes', scale=alt.Scale(type='symlog'), title='Packet Size (Bytes)'),
                y=alt.Y('count', scale=alt.Scale(type='symlog'), title='Traffic Count'),
                color=alt.Color('DT Analysis', scale=alt.Scale(domain=['✅ Normal', '🚨 ATTACK'], range=['#00CC96', '#EF553B'])),
                tooltip=['src_ip', 'src_bytes', 'count', 'DT Analysis']
            ).properties(height=300, title="Volume vs Size").interactive()
            st.altair_chart(scatter_chart, use_container_width=True)
            
            # 5. AI SUMMARY
            generate_smart_summary(df_display, 'DT Analysis', 'Decision Tree')
            
    except Exception as e:
        st.error(f"Error: {e}")

# --- 7. UI Layout ---
tab1, tab2, tab3 = st.tabs(["📡 Live Capture", "📂 Upload Wireshark File", "🧠 Model Logic"])

# === TAB 1: Live Capture ===
with tab1:
    st.subheader("Live Network Sniffer")
    
    c1, c2 = st.columns([1, 4])
    with c1:
        start = st.button("▶️ Start Capture")
        stop = st.button("⏹️ Stop Capture")
        
    live_placeholder = st.empty()
    
    if 'continuous_df' not in st.session_state:
        st.session_state.continuous_df = pd.DataFrame()
        
    if 'is_running' not in st.session_state:
        st.session_state.is_running = False
        
    if start:
        st.session_state.is_running = True
    if stop:
        st.session_state.is_running = False
        
    if st.session_state.is_running:
        with st.spinner("Monitoring Network..."):
            while st.session_state.is_running:
                pkt_batch = sniff(count=1, timeout=1)
                
                if pkt_batch:
                    new_row = packets_to_df(pkt_batch)
                    st.session_state.continuous_df = pd.concat([st.session_state.continuous_df, new_row], ignore_index=True)
                    
                    if len(st.session_state.continuous_df) > 100:
                        st.session_state.continuous_df = st.session_state.continuous_df.tail(100)
                    
                    with live_placeholder.container():
                        display_results(st.session_state.continuous_df, "continuous", allow_download=False)
                
                time.sleep(0.1) 
                
    elif not st.session_state.continuous_df.empty:
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
                    st.session_state['upload_data'] = packets_to_df(packets)
                    st.session_state['last_file'] = uploaded_file.name
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
