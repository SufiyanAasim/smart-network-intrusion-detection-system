from nids import netcheck


class _Interface:
    def __init__(self, name, network_name="", description="", ip=""):
        self.name = name
        self.network_name = network_name
        self.description = description
        self.ip = ip


def test_capture_readiness_ready_on_windows_when_provider_available(monkeypatch):
    monkeypatch.setattr(netcheck, "pcap_provider_available", lambda: True)
    monkeypatch.setattr(netcheck.platform, "system", lambda: "Windows")
    ready, message = netcheck.capture_readiness()
    assert ready is True
    assert message == ""


def test_capture_readiness_windows_mentions_npcap(monkeypatch):
    monkeypatch.setattr(netcheck, "pcap_provider_available", lambda: False)
    monkeypatch.setattr(netcheck.platform, "system", lambda: "Windows")
    ready, message = netcheck.capture_readiness()
    assert ready is False
    assert "Npcap" in message
    assert netcheck.NPCAP_URL in message


def test_capture_readiness_linux_ready_without_libpcap(monkeypatch):
    """scapy captures via native raw sockets on Linux, so a missing libpcap
    provider must NOT disable capture there."""
    monkeypatch.setattr(netcheck, "pcap_provider_available", lambda: False)
    monkeypatch.setattr(netcheck.platform, "system", lambda: "Linux")
    ready, message = netcheck.capture_readiness()
    assert ready is True
    assert message == ""


def test_capture_readiness_macos_ready_without_libpcap(monkeypatch):
    monkeypatch.setattr(netcheck, "pcap_provider_available", lambda: False)
    monkeypatch.setattr(netcheck.platform, "system", lambda: "Darwin")
    ready, message = netcheck.capture_readiness()
    assert ready is True
    assert message == ""


def test_privilege_hint_is_platform_specific(monkeypatch):
    monkeypatch.setattr(netcheck.platform, "system", lambda: "Windows")
    assert "Npcap" in netcheck.privilege_hint()
    monkeypatch.setattr(netcheck.platform, "system", lambda: "Linux")
    assert "CAP_NET_RAW" in netcheck.privilege_hint()


def test_capture_interfaces_builds_stable_friendly_options(monkeypatch):
    from scapy.all import conf

    interfaces = {
        "a": _Interface("Ethernet", "npcap-a", "Intel Ethernet", "192.0.2.10"),
        "b": _Interface("Wi-Fi", "npcap-b", "Wi-Fi", "198.51.100.4"),
    }
    monkeypatch.setattr(conf.ifaces, "values", lambda: interfaces.values())

    result = netcheck.capture_interfaces()

    assert {item.identifier for item in result} == {"npcap-a", "npcap-b"}
    assert any(item.label == "Intel Ethernet · 192.0.2.10" for item in result)


def test_default_capture_interface_honours_environment(monkeypatch):
    interfaces = [
        netcheck.CaptureInterface("one", "Ethernet"),
        netcheck.CaptureInterface("two", "Wi-Fi"),
    ]
    monkeypatch.setenv(netcheck.CAPTURE_INTERFACE_ENV, "two")
    assert netcheck.default_capture_interface(interfaces) == "two"


def test_default_capture_interface_falls_back_to_first(monkeypatch):
    interfaces = [netcheck.CaptureInterface("one", "Ethernet")]
    monkeypatch.delenv(netcheck.CAPTURE_INTERFACE_ENV, raising=False)
    assert netcheck.default_capture_interface(interfaces) == "one"
    assert netcheck.default_capture_interface([]) is None
