from nids import geo


def test_classify_ip_categories():
    assert geo.classify_ip("10.0.0.1") == "private"
    assert geo.classify_ip("192.168.1.5") == "private"
    assert geo.classify_ip("127.0.0.1") == "loopback"
    assert geo.classify_ip("8.8.8.8") == "public"
    assert geo.classify_ip("224.0.0.1") == "reserved"
    assert geo.classify_ip("not-an-ip") == "invalid"


def test_categorize_ips_counts():
    counts = geo.categorize_ips(["10.0.0.1", "10.0.0.2", "8.8.8.8", "127.0.0.1"])
    assert counts == {"private": 2, "public": 1, "loopback": 1}


def test_geoip_available_false_without_db(monkeypatch):
    monkeypatch.delenv(geo.GEOIP_DB_ENV, raising=False)
    assert geo.geoip_available() is False


def test_resolve_locations_empty_without_db(monkeypatch):
    monkeypatch.delenv(geo.GEOIP_DB_ENV, raising=False)
    assert geo.resolve_locations(["8.8.8.8"]) == []
