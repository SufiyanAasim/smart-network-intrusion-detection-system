"""Pure feature-engineering logic for the NSL-KDD based IDS.

Kept free of Streamlit imports so it can be unit tested and reused
(e.g. by a training script) without a Streamlit runtime.
"""

import pandas as pd
from scapy.all import IP, TCP, UDP

# NSL-KDD's "count"/"srv_count" style features are defined over the trailing
# 2 seconds and the most recent 100 connections. We approximate that here
# using each packet's own capture timestamp against the other packets passed
# into packets_to_df, rather than a single hardcoded value.
WINDOW_SECONDS = 2.0
WINDOW_CONNECTIONS = 100

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


def _is_error(pkt):
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        if 'S' in flags and 'A' not in flags:
            return True
        if 'R' in flags:
            return True
    return False


def packets_to_df(packets):
    """Convert a scapy packet list into a DataFrame shaped like NSL-KDD records.

    `count`/`srv_count`/`*serror_rate`/`*same_srv_rate` are computed from a
    trailing window (<=WINDOW_SECONDS old, <=WINDOW_CONNECTIONS packets) of
    packets to the same destination IP, ordered by capture timestamp — not a
    static value — so they reflect actual recent traffic to that host.
    """
    ip_packets = [pkt for pkt in packets if pkt.haslayer(IP)]
    if not ip_packets:
        return pd.DataFrame()

    ip_packets = sorted(ip_packets, key=lambda p: float(p.time))

    captured_data = []
    for idx, pkt in enumerate(ip_packets):
        now = float(pkt.time)
        dst_ip = pkt[IP].dst
        service = _get_service(pkt)

        window = [
            p for p in ip_packets[max(0, idx - WINDOW_CONNECTIONS + 1):idx + 1]
            if now - float(p.time) <= WINDOW_SECONDS
        ]
        same_host = [p for p in window if p[IP].dst == dst_ip]
        same_host_srv = [p for p in same_host if _get_service(p) == service]

        count = len(same_host)
        srv_count = len(same_host_srv)
        error_count = sum(1 for p in same_host if _is_error(p))
        srv_error_count = sum(1 for p in same_host_srv if _is_error(p))

        serror_rate = error_count / count if count else 0.0
        srv_serror_rate = srv_error_count / srv_count if srv_count else 0.0
        same_srv_rate = srv_count / count if count else 0.0
        diff_srv_rate = 1.0 - same_srv_rate

        row = {col: 0 for col in MODEL_FEATURES}
        row['src_ip'] = pkt[IP].src
        row['dst_ip'] = dst_ip
        row['protocol_type'] = 'tcp' if pkt.haslayer(TCP) else 'udp' if pkt.haslayer(UDP) else 'icmp'
        row['service'] = service
        row['flag'] = _get_flag(pkt)
        row['src_bytes'] = len(pkt[IP].payload)

        row['count'] = count
        row['srv_count'] = srv_count
        row['dst_host_count'] = count
        row['dst_host_srv_count'] = srv_count

        row['serror_rate'] = serror_rate
        row['srv_serror_rate'] = srv_serror_rate
        row['dst_host_serror_rate'] = serror_rate
        row['dst_host_srv_serror_rate'] = srv_serror_rate

        row['same_srv_rate'] = same_srv_rate
        row['diff_srv_rate'] = diff_srv_rate
        row['dst_host_same_srv_rate'] = same_srv_rate
        row['dst_host_diff_srv_rate'] = diff_srv_rate

        captured_data.append(row)

    return pd.DataFrame(captured_data)
