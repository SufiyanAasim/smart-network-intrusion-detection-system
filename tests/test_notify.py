from nids import notify


def test_beep_wav_bytes_is_valid_wav():
    data = notify.beep_wav_bytes(duration_seconds=0.05)
    assert data[:4] == b"RIFF"
    assert data[8:12] == b"WAVE"


def test_beep_data_uri_prefix():
    uri = notify.beep_data_uri()
    assert uri.startswith("data:audio/wav;base64,")


def test_alert_html_includes_enabled_channels():
    html = notify.alert_html("attack from 10.0.0.1", play_sound=True, browser_notification=True, nonce="1")
    assert "<audio" in html
    assert "Notification" in html
    assert "nonce:1" in html


def test_alert_html_omits_disabled_channels():
    html = notify.alert_html("x", play_sound=False, browser_notification=False, nonce="2")
    assert "<audio" not in html
    assert "Notification" not in html


def test_alert_html_escapes_quotes():
    html = notify.alert_html('say "hi"', play_sound=False, browser_notification=True, nonce="3")
    assert '\\"hi\\"' in html
