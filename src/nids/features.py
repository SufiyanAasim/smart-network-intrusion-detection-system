"""Pure feature-engineering logic for the NSL-KDD based IDS.

Kept free of Streamlit imports so it can be unit tested and reused
(e.g. by a training script) without a Streamlit runtime.
"""

from collections import Counter

import pandas as pd
from scapy.all import IP, TCP, UDP

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
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
]


def preprocess_data(df, encoders):
    """Label-encode categorical columns, mapping unseen categories to a known class."""
    df_encoded = df.copy()
    for col, le in encoders.items():
        if col in df_encoded.columns:
            known_classes = set(le.classes_)
            df_encoded[col] = df_encoded[col].apply(lambda x: x if x in known_classes else list(known_classes)[0])
            df_encoded[col] = le.transform(df_encoded[col])
    return df_encoded


def _get_service(pkt):
    if pkt.haslayer(TCP):
        port = pkt[TCP].dport
        if port == 80:
            return 'http'
        if port == 21:
            return 'ftp'
        if port == 22:
            return 'ssh'
    return 'other'


def _get_flag(pkt):
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        if 'S' in flags and 'A' not in flags:
            return 'S0'
        if 'R' in flags:
            return 'REJ'
    return 'SF'


def packets_to_df(packets):
    """Convert a scapy packet list into a DataFrame shaped like NSL-KDD records."""
    captured_data = []
    dst_ip_counts = Counter()
    error_counts = Counter()

    for pkt in packets:
        if pkt.haslayer(IP):
            dst_ip_counts[pkt[IP].dst] += 1
        is_error = False
        if pkt.haslayer(TCP):
            if 'S' in pkt[TCP].flags and 'A' not in pkt[TCP].flags:
                is_error = True
            if 'R' in pkt[TCP].flags:
                is_error = True
        if is_error and pkt.haslayer(IP):
            error_counts[pkt[IP].dst] += 1

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        row = {col: 0 for col in MODEL_FEATURES}
        row['src_ip'] = pkt[IP].src
        row['dst_ip'] = pkt[IP].dst
        row['protocol_type'] = 'tcp' if pkt.haslayer(TCP) else 'udp' if pkt.haslayer(UDP) else 'icmp'
        row['service'] = _get_service(pkt)
        row['flag'] = _get_flag(pkt)
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
