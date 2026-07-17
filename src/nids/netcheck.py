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

    scapy sets conf.use_pcap when a libpcap/Npcap provider is present. Note
    this is only *required* on Windows — see capture_readiness().
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

    Only Windows genuinely requires a pcap provider (Npcap): scapy has no
    native capture backend there. On Linux/macOS scapy captures through
    native raw sockets and conf.use_pcap is normally False even though
    capture works fine, so gating those platforms on use_pcap would disable
    the Start button for no reason. There the real gate is root/CAP_NET_RAW,
    which can't be probed without attempting a capture, so we report ready
    and let scapy surface a permission error if privileges are missing.
    """
    system = platform.system()

    if system == "Windows":
        if pcap_provider_available():
            return True, ""
        return False, (
            "No packet-capture driver detected. Live capture needs **Npcap** "
            f"installed. Download it from {NPCAP_URL} (enable *WinPcap API "
            "compatibility* during install), then restart this app. "
            "Pcap upload works without it."
        )

    # Linux/macOS: native raw-socket capture works without libpcap.
    return True, ""


def privilege_hint():
    """A short note on the privileges live capture needs on this platform.

    Advisory only — shown alongside the capture controls rather than used to
    block them, since privileges can't be checked without trying to capture.
    """
    system = platform.system()
    if system == "Windows":
        return "Live capture needs Npcap and an Administrator terminal."
    if system == "Darwin":
        return "Live capture needs root (e.g. run with `sudo`)."
    return "Live capture needs root (`sudo`) or `CAP_NET_RAW` on the interpreter."
