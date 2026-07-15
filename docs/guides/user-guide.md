# User Guide

## Live Capture tab

1. Click **▶️ Start Capture**. Requires raw-socket privileges (run as
   admin/root, or grant `CAP_NET_RAW` on Linux).
2. Packets are classified as they arrive; the last 100 packets are kept
   in memory and shown in the tables/charts.
3. Click **⏹️ Stop Capture** to pause and enable CSV download.

## Upload Wireshark File tab

1. Upload a `.pcap`/`.pcapng` file (sample files: `data/pcaps/`).
2. The file is parsed, classified, and the report + CSV download appear.
3. Removing the uploaded file clears the session state.

## Model Logic tab

Shows the top-10 most important features for each model
(`rf_model.feature_importances_` / `dt_model.feature_importances_`).

## Reading the summary

- **SAFE** — 0% flagged as attack.
- **SUSPICIOUS** — under 20% flagged; monitor the listed IPs.
- **CRITICAL THREAT** — 20%+ flagged; shows the most likely attacker/victim IP.
