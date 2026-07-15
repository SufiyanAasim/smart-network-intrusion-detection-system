import streamlit as st
import pandas as pd
import numpy as np
import joblib
from scapy.all import sniff, rdpcap, IP, TCP, UDP
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score
import os
import tempfile
import altair as alt
from collections import Counter
import time

# --- 1. Page Configuration ---
st.set_page_config(page_title="Network Intrusion Detection", layout="wide")

st.title("🛡️ AI Network Intrusion Detection System")
st.markdown("Compare **Random Forest** and **Decision Tree** models side-by-side.")

# --- 2. Smart Path Finding ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def get_path(filename):
    return os.path.join(BASE_DIR, filename)

# --- 3. Helper Functions ---
MODEL_FEATURES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

def preprocess_data(df, encoders):
    df_encoded = df.copy()
    for col, le in encoders.items():
        if col in df_encoded.columns:
            known_classes = set(le.classes_)
            df_encoded[col] = df_encoded[col].apply(lambda x: x if x in known_classes else list(known_classes)[0])
            df_encoded[col] = le.transform(df_encoded[col])
    return df_encoded

# --- 4. Load Resources ---
@st.cache_resource
def load_resources():
    try:
        rf_model = joblib.load(get_path('rf_model.pkl'))
        dt_model = joblib.load(get_path('dt_model.pkl'))
        
        columns = MODEL_FEATURES + ['label', 'difficulty_level']
        
        train_path = get_path('KDDTrain+.txt')
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
            
        test_path = get_path('KDDTest+.txt')
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

# --- 5. Feature Engineering ---
def packets_to_df(packets):
    captured_data = []
    dst_ip_counts = Counter()
    dst_port_counts = Counter()
    error_counts = Counter()
    
    for pkt in packets:
        if pkt.haslayer(IP):
            dst_ip_counts[pkt[IP].dst] += 1
        is_error = False
        if pkt.haslayer(TCP):
            dst_port_counts[pkt[TCP].dport] += 1
            if 'S' in pkt[TCP].flags and 'A' not in pkt[TCP].flags: is_error = True
            if 'R' in pkt[TCP].flags: is_error = True
        elif pkt.haslayer(UDP):
            dst_port_counts[pkt[UDP].dport] += 1
        if is_error and pkt.haslayer(IP):
            error_counts[pkt[IP].dst] += 1

    def get_service(pkt):
        if pkt.haslayer(TCP):
            port = pkt[TCP].dport
            if port == 80: return 'http'
            if port == 21: return 'ftp'
            if port == 22: return 'ssh'
        return 'other'

    def get_flag(pkt):
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if 'S' in flags and 'A' not in flags: return 'S0' 
            if 'R' in flags: return 'REJ'
        return 'SF'

    for pkt in packets:
        if pkt.haslayer(IP):
            row = {col: 0 for col in MODEL_FEATURES}
            row['src_ip'] = pkt[IP].src
            row['dst_ip'] = pkt[IP].dst
            row['protocol_type'] = 'tcp' if pkt.haslayer(TCP) else 'udp' if pkt.haslayer(UDP) else 'icmp'
            row['service'] = get_service(pkt)
            row['flag'] = get_flag(pkt)
            row['src_bytes'] = len(pkt[IP].payload)
            
            count = dst_ip_counts[pkt[IP].dst]
            row['count'] = count
            row['srv_count'] = count
            row['dst_host_count'] = count
            row['dst_host_srv_count'] = count
            
            error_count = error_counts[pkt[IP].dst]
            error_rate = error_count / count if count > 0 else 0
            
            row['serror_rate'] = error_rate
            row['dst_host_serror_rate'] = error_rate
            row['same_srv_rate'] = 1.0
            row['dst_host_same_srv_rate'] = 1.0
            
            captured_data.append(row)
            
    return pd.DataFrame(captured_data)

# --- 6. AI Summary Generator ---
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
