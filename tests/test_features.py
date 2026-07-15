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

    assert encoded["protocol_type"].tolist() == le.transform(["tcp", "tcp"]).tolist()


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
