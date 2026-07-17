"""Capture-capability checks for the live sniffer.

Live capture needs a working packet-capture provider. On Windows that means
Npcap; on Linux/macOS it means libpcap plus raw-socket privileges. This
module answers "can we actually capture?" so the UI can show a helpful
banner instead of silently returning zero packets.

Kept free of Streamlit imports so it can be unit tested directly.
"""

from dataclasses import dataclass
import os
import platform

NPCAP_URL = "https://npcap.com/#download"
CAPTURE_INTERFACE_ENV = "NIDS_CAPTURE_INTERFACE"


@dataclass(frozen=True)
class CaptureInterface:
    """A stable capture-adapter identifier plus a human-readable label."""

    identifier: str
    label: str
    address: str = ""


def _interface_value(interface, name):
    """Safely read a Scapy interface attribute without leaking backend errors."""
    try:
        return str(getattr(interface, name, "") or "").strip()
    except Exception:
        return ""


def capture_interfaces():
    """Return the capture adapters currently exposed by Scapy.

    Windows capture uses ``network_name`` (the Npcap device identifier), while
    Linux/macOS normally use ``name``. Duplicate and unusable entries are
    removed, and labels include the interface IP where Scapy provides one.
    """
    try:
        # Import through scapy.all so Windows providers populate conf.ifaces;
        # importing scapy.config alone can leave the registry empty until a
        # packet layer initializes Scapy elsewhere in the process.
        from scapy.all import conf

        interfaces = list(conf.ifaces.values())
    except Exception:
        return []

    results = []
    seen = set()
    for interface in interfaces:
        identifier = (
            _interface_value(interface, "network_name")
            or _interface_value(interface, "name")
        )
        if not identifier or identifier in seen:
            continue
        seen.add(identifier)
        name = _interface_value(interface, "name") or identifier
        description = _interface_value(interface, "description")
        address = _interface_value(interface, "ip")
        display_name = description if description and description != name else name
        label = f"{display_name} · {address}" if address and address != "0.0.0.0" else display_name
        results.append(CaptureInterface(identifier, label, address))

    return sorted(results, key=lambda item: item.label.casefold())


def default_capture_interface(interfaces):
    """Choose the configured/Scapy-default adapter from ``interfaces``.

    ``NIDS_CAPTURE_INTERFACE`` wins when it matches either an identifier or a
    display label. Otherwise Scapy's route-selected default is used, followed
    by the first listed adapter.
    """
    options = list(interfaces)
    if not options:
        return None

    requested = os.environ.get(CAPTURE_INTERFACE_ENV, "").strip()
    if requested:
        for option in options:
            if requested in (option.identifier, option.label):
                return option.identifier

    try:
        from scapy.all import conf

        default_identifier = (
            _interface_value(conf.iface, "network_name")
            or _interface_value(conf.iface, "name")
            or str(conf.iface)
        )
    except Exception:
        default_identifier = ""
    for option in options:
        if option.identifier == default_identifier:
            return option.identifier
    return options[0].identifier


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
    import os
    if os.environ.get("RENDER"):
        return False, (
            "Live capture is disabled in the cloud. Cloud containers "
            "do not have access to local network interfaces or raw-socket capture capabilities. "
            "Use the **Upload Wireshark File** tab to analyze packet capture files."
        )

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
        return (
            "Live capture uses Npcap. If capture is denied by your Npcap "
            "access policy, relaunch from an Administrator terminal."
        )
    if system == "Darwin":
        return "Live capture needs root (e.g. run with `sudo`)."
    return "Live capture needs root (`sudo`) or `CAP_NET_RAW` on the interpreter."
