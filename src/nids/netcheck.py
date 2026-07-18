"""Capture-capability checks for the live sniffer.

Live capture needs a working packet-capture provider. On Windows that means
Npcap; on Linux/macOS it means libpcap plus raw-socket privileges. This
module answers "can we actually capture?" so the UI can show a helpful
banner instead of silently returning zero packets.

Kept free of Streamlit imports so it can be unit tested directly.
"""

import platform

NPCAP_URL = "https://npcap.com/#download"


def pcap_provider_available():
    """True if scapy reports a usable libpcap/Npcap provider.

    scapy sets conf.use_pcap and populates conf.L2socket when a provider is
    present. We check conf.use_pcap, tolerating scapy import/attribute
    errors by returning False (capture won't work anyway).
    """
    try:
        from scapy.config import conf
    except Exception:
        return False
    return bool(getattr(conf, "use_pcap", False))


def capture_readiness():
    """Return (ready: bool, message: str) describing capture capability.

    `message` is empty when ready, otherwise a human-readable explanation
    with the platform-appropriate fix.
    """
    if pcap_provider_available():
        return True, ""

    system = platform.system()
    if system == "Windows":
        return False, (
            "No packet-capture driver detected. Live capture needs **Npcap** "
            f"installed. Download it from {NPCAP_URL} (enable *WinPcap API "
            "compatibility* during install), then restart this app. "
            "Pcap upload works without it."
        )
    if system == "Darwin":
        return False, (
            "No libpcap provider available. On macOS, run the app with "
            "sufficient privileges (e.g. `sudo`) for raw-socket capture. "
            "Pcap upload works without it."
        )
    return False, (
        "No libpcap provider available. On Linux, install libpcap and run "
        "with raw-socket privileges (`sudo`, or grant the interpreter "
        "`CAP_NET_RAW`). Pcap upload works without it."
    )
