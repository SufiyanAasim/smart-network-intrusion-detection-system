import pandas as pd
from sklearn.preprocessing import LabelEncoder

from nids.features import MODEL_FEATURES, packets_to_df, preprocess_data


def test_model_features_has_41_nsl_kdd_columns():
    assert len(MODEL_FEATURES) == 41


def test_preprocess_data_maps_unseen_category_to_known_class():
    le = LabelEncoder()
    le.fit(["tcp", "udp"])
    df = pd.DataFrame({"protocol_type": ["tcp", "icmp"]})

    encoded = preprocess_data(df, {"protocol_type": le})

    # Known categories pass through unchanged.
    assert encoded["protocol_type"].iloc[0] == le.transform(["tcp"])[0]
    # Unseen categories deterministically map to LabelEncoder's first class.
    assert encoded["protocol_type"].iloc[1] == le.transform([le.classes_[0]])[0]


def test_packets_to_df_empty_input_returns_empty_dataframe():
    result = packets_to_df([])
    assert result.empty


def test_packets_to_df_extracts_tcp_syn_as_error_flag():
    from scapy.all import IP, TCP

    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80, flags="S")
    df = packets_to_df([pkt])

    assert len(df) == 1
    assert df.iloc[0]["flag"] == "S0"
    assert df.iloc[0]["service"] == "http"
    assert df.iloc[0]["protocol_type"] == "tcp"


def test_packets_to_df_computes_rolling_window_count_and_error_rate():
    from scapy.all import IP, TCP

    base_time = 1000.0
    packets = []
    for i in range(5):
        pkt = IP(src="10.0.0.1", dst="10.0.0.9") / TCP(dport=80, flags="S")
        pkt.time = base_time + i * 0.1
        packets.append(pkt)

    df = packets_to_df(packets)

    assert len(df) == 5
    last_row = df.iloc[-1]
    assert last_row["count"] == 5
    assert last_row["srv_count"] == 5
    assert last_row["serror_rate"] == 1.0
    assert last_row["same_srv_rate"] == 1.0


def test_packets_to_df_excludes_packets_outside_2_second_window():
    from scapy.all import IP, TCP

    old_pkt = IP(src="10.0.0.1", dst="10.0.0.9") / TCP(dport=80, flags="S")
    old_pkt.time = 1000.0

    new_pkt = IP(src="10.0.0.1", dst="10.0.0.9") / TCP(dport=80, flags="S")
    new_pkt.time = 1005.0  # 5s later, outside the 2s window

    df = packets_to_df([old_pkt, new_pkt])

    assert df.iloc[-1]["count"] == 1
