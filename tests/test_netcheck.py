from nids import netcheck


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
