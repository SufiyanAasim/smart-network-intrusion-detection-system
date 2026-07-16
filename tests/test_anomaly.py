from nids.anomaly import to_binary, to_verdict


def test_to_verdict_maps_outlier_to_attack_and_inlier_to_normal():
    assert to_verdict([1, -1, 1]) == ['✅ Normal', '🚨 ATTACK', '✅ Normal']


def test_to_binary_maps_outlier_to_1_and_inlier_to_0():
    assert to_binary([1, -1, 1]) == [0, 1, 0]
