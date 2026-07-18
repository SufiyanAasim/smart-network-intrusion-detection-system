from unittest.mock import patch

from nids import alerts


def test_send_slack_alert_returns_false_when_unconfigured(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    assert alerts.send_slack_alert("test") is False


def test_send_slack_alert_posts_when_configured():
    with patch("nids.alerts.urllib.request.urlopen") as mock_urlopen:
        result = alerts.send_slack_alert("test message", webhook_url="https://hooks.example/x")

    assert result is True
    mock_urlopen.assert_called_once()


def test_send_email_alert_returns_false_when_unconfigured():
    assert alerts.send_email_alert("subject", "body", config=None) is False


def test_send_critical_alert_never_raises_when_a_channel_fails(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("ALERT_SMTP_HOST", raising=False)

    sent = alerts.send_critical_alert("Random Forest", 42.0, "10.0.0.1", "10.0.0.9")

    assert sent == []


def test_send_critical_alert_reports_successful_channels():
    with patch("nids.alerts.send_slack_alert", return_value=True), \
         patch("nids.alerts.send_webhook_alert", return_value=False), \
         patch("nids.alerts.send_email_alert", side_effect=RuntimeError("smtp down")):
        sent = alerts.send_critical_alert("Decision Tree", 55.0, "10.0.0.1", "10.0.0.9")

    assert sent == ["slack"]
