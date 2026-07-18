from nids import throughput


def test_aggregate_per_second_sums_within_second():
    samples = [
        {"t": 100, "packets": 1, "bytes": 512},
        {"t": 100, "packets": 2, "bytes": 512},
        {"t": 101, "packets": 1, "bytes": 1024},
    ]
    agg = throughput.aggregate_per_second(samples)

    assert list(agg["second"]) == [100, 101]
    assert list(agg["packets"]) == [3, 1]
    assert agg.iloc[0]["kbytes"] == 1.0  # 1024 bytes / 1024
    assert agg.iloc[1]["kbytes"] == 1.0


def test_aggregate_per_second_empty():
    agg = throughput.aggregate_per_second([])
    assert agg.empty
    assert list(agg.columns) == ["second", "packets", "kbytes"]


def test_trim_samples_drops_old():
    samples = [
        {"t": 10, "packets": 1, "bytes": 1},
        {"t": 65, "packets": 1, "bytes": 1},
        {"t": 70, "packets": 1, "bytes": 1},
    ]
    trimmed = throughput.trim_samples(samples, max_seconds=60, now=71)
    assert [r["t"] for r in trimmed] == [65, 70]


def test_trim_samples_empty():
    assert throughput.trim_samples([]) == []
