from nids import netcheck


def test_capture_readiness_ready_when_provider_available(monkeypatch):
    monkeypatch.setattr(netcheck, "pcap_provider_available", lambda: True)
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


def test_capture_readiness_linux_mentions_libpcap(monkeypatch):
    monkeypatch.setattr(netcheck, "pcap_provider_available", lambda: False)
    monkeypatch.setattr(netcheck.platform, "system", lambda: "Linux")
    ready, message = netcheck.capture_readiness()
    assert ready is False
    assert "libpcap" in message
