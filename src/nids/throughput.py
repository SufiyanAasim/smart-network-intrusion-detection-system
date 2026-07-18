"""Per-second throughput aggregation for the live sniffer.

The live-capture loop records one sample per captured batch as
`{"t": <epoch_seconds:int>, "packets": int, "bytes": int}`. These helpers
aggregate those raw samples into a per-second series for a live line chart.

Kept free of Streamlit imports so it can be unit tested directly.
"""

import pandas as pd


def aggregate_per_second(samples):
    """Aggregate raw capture samples into a per-second DataFrame.

    Input: iterable of {"t": int_epoch_second, "packets": int, "bytes": int}.
    Output: DataFrame with columns [second, packets, kbytes] sorted by
    second, one row per distinct second (summing samples in that second).
    Returns an empty DataFrame for empty input.
    """
    rows = list(samples)
    if not rows:
        return pd.DataFrame(columns=["second", "packets", "kbytes"])

    df = pd.DataFrame(rows)
    grouped = (
        df.groupby("t", as_index=False)[["packets", "bytes"]]
        .sum()
        .sort_values("t")
    )
    grouped["kbytes"] = grouped["bytes"] / 1024.0
    grouped = grouped.rename(columns={"t": "second"})
    return grouped[["second", "packets", "kbytes"]]


def trim_samples(samples, max_seconds=60, now=None):
    """Drop samples older than `max_seconds` relative to `now` (or the latest
    sample's second if `now` is None). Keeps the live chart to a fixed window.
    """
    rows = list(samples)
    if not rows:
        return rows
    reference = now if now is not None else max(r["t"] for r in rows)
    cutoff = reference - max_seconds
    return [r for r in rows if r["t"] >= cutoff]
