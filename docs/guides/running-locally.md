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

## Windows live capture

Wireshark is **not required**. Install Npcap, keep **WinPcap API-compatible
mode** enabled in its installer, then restart the dashboard. In **Live Capture**:

1. Choose the Ethernet, Wi-Fi, VPN, or virtual adapter carrying the traffic.
2. Click **Start Capture**.
3. Generate traffic on this computer and confirm the packet counter advances.

The selected adapter captures traffic visible to this computer. A switched
network does not automatically send other devices' unicast traffic to it. For
whole-LAN monitoring, mirror traffic to this machine with a managed switch
SPAN/port-mirroring port, use a network TAP, or run NIDS on the gateway/router.
Wireshark remains optional and is useful only when you want deeper manual packet
inspection or need to create a `.pcap`/`.pcapng` for the upload workflow.

## Local roles and account creation

Copy `.env.example` to `.env`, provision Administrator/Viewer hashes through
`NIDS_AUTH_USERS`, and set `NIDS_SIGNUP_ENABLED=true` only on a trusted local
installation. The app provides separate **Sign in** and **Create account**
screens. New self-service accounts are always Viewers and are stored as salted
PBKDF2 hashes in `data/auth.db`; an unauthenticated user cannot create an
Administrator account.

## Notes

- Live packet capture (Tab 1) needs elevated privileges:
  - **Windows:** install Npcap. Administrator is needed only when Npcap was
    installed in admin-only mode or Windows denies interface access.
  - **Linux/macOS:** run with `sudo`, or grant the interpreter `CAP_NET_RAW`
    (`sudo setcap cap_net_raw+ep $(readlink -f $(which python3))`).
- Pcap upload (Tab 2) works without Npcap, Wireshark, or elevated privileges.
- To retrain the models instead of using the ones in `models/`, run
  `python scripts/train_models.py`.
