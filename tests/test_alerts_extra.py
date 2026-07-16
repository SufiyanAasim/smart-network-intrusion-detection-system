from unittest.mock import patch

from nids import alerts


def test_teams_alert_returns_false_when_unconfigured(monkeypatch):
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    assert alerts.send_teams_alert("x") is False


def test_teams_alert_posts_messagecard_when_configured():
    with patch("nids.alerts._post_json") as mock_post:
        result = alerts.send_teams_alert("hi", webhook_url="https://teams.example/x")
    assert result is True
    url, payload = mock_post.call_args[0]
    assert payload["@type"] == "MessageCard"
    assert payload["text"] == "hi"


def test_pagerduty_alert_returns_false_when_unconfigured(monkeypatch):
    monkeypatch.delenv("PAGERDUTY_ROUTING_KEY", raising=False)
    assert alerts.send_pagerduty_alert("x", "summary") is False


def test_pagerduty_alert_triggers_event_v2():
    with patch("nids.alerts._post_json") as mock_post:
        result = alerts.send_pagerduty_alert("body", "summary", routing_key="RK")
    assert result is True
    url, payload = mock_post.call_args[0]
    assert url.endswith("/v2/enqueue")
    assert payload["routing_key"] == "RK"
    assert payload["event_action"] == "trigger"
    assert payload["payload"]["severity"] == "critical"


def test_send_critical_alert_includes_new_channels(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("ALERT_SMTP_HOST", raising=False)
    with patch("nids.alerts.send_teams_alert", return_value=True), \
         patch("nids.alerts.send_pagerduty_alert", return_value=True):
        sent = alerts.send_critical_alert("RF", 40.0, "10.0.0.1", "10.0.0.9")
    assert "teams" in sent
    assert "pagerduty" in sent
