# Running Locally

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. From the repo root, start the dashboard:
   ```bash
   streamlit run src/nids/app.py
   ```
3. Open the URL Streamlit prints (default `http://localhost:8501`).

## Notes

- Live packet capture (Tab 1) needs elevated privileges:
  - **Windows:** run your terminal as Administrator.
  - **Linux/macOS:** run with `sudo`, or grant the interpreter `CAP_NET_RAW`
    (`sudo setcap cap_net_raw+ep $(readlink -f $(which python3))`).
- Pcap upload (Tab 2) works without elevated privileges.
- To retrain the models instead of using the ones in `models/`, run
  `python scripts/train_models.py`.
