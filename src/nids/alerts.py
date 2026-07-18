"""Alerting for critical-threat detections.

Channels: Slack, generic webhook, email, PagerDuty (Events API v2), and
Microsoft Teams. Every channel is optional and configured entirely via
environment variables, so the app runs with zero alerting configured (calls
just no-op). Kept free of Streamlit imports so it's independently
testable/mockable.
"""

import json
import os
import smtplib
import urllib.request
from email.message import EmailMessage


def _slack_webhook_url():
    return os.environ.get("SLACK_WEBHOOK_URL")


def _generic_webhook_url():
    return os.environ.get("ALERT_WEBHOOK_URL")


def _pagerduty_routing_key():
    return os.environ.get("PAGERDUTY_ROUTING_KEY")


def _teams_webhook_url():
    return os.environ.get("TEAMS_WEBHOOK_URL")


def _email_config():
    host = os.environ.get("ALERT_SMTP_HOST")
    if not host:
        return None
    return {
        "host": host,
        "port": int(os.environ.get("ALERT_SMTP_PORT", "587")),
        "username": os.environ.get("ALERT_SMTP_USERNAME"),
        "password": os.environ.get("ALERT_SMTP_PASSWORD"),
        "from_addr": os.environ.get("ALERT_EMAIL_FROM"),
        "to_addr": os.environ.get("ALERT_EMAIL_TO"),
    }


def _post_json(url, payload_dict, timeout=5):
    payload = json.dumps(payload_dict).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=timeout)  # noqa: S310 - trusted, user-configured URL


def send_slack_alert(message, webhook_url=None):
    url = webhook_url or _slack_webhook_url()
    if not url:
        return False
    _post_json(url, {"text": message})
    return True


def send_webhook_alert(message, webhook_url=None):
    url = webhook_url or _generic_webhook_url()
    if not url:
        return False
    _post_json(url, {"text": message})
    return True


def send_teams_alert(message, webhook_url=None):
    """Post to a Microsoft Teams incoming webhook (MessageCard format)."""
    url = webhook_url or _teams_webhook_url()
    if not url:
        return False
    _post_json(url, {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": "NIDS critical threat",
        "themeColor": "EF553B",
        "title": "🚨 NIDS: Critical threat detected",
        "text": message,
    })
    return True


def send_pagerduty_alert(message, summary, routing_key=None):
    """Trigger a PagerDuty incident via Events API v2."""
    key = routing_key or _pagerduty_routing_key()
    if not key:
        return False
    _post_json("https://events.pagerduty.com/v2/enqueue", {
        "routing_key": key,
        "event_action": "trigger",
        "payload": {
            "summary": summary,
            "source": "nids",
            "severity": "critical",
            "custom_details": {"message": message},
        },
    })
    return True


def send_email_alert(subject, message, config=None):
    cfg = config or _email_config()
    if not cfg or not cfg.get("to_addr") or not cfg.get("from_addr"):
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["from_addr"]
    msg["To"] = cfg["to_addr"]
    msg.set_content(message)

    with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as smtp:
        smtp.starttls()
        if cfg.get("username") and cfg.get("password"):
            smtp.login(cfg["username"], cfg["password"])
        smtp.send_message(msg)
    return True


def send_critical_alert(model_name, attack_pct, top_attacker, top_victim):
    """Fan out a critical-threat alert to every configured channel.

    Returns the list of channel names that were actually sent (empty if
    nothing is configured). A failure in one channel never blocks another,
    and alerting must never crash the dashboard.
    """
    message = (
        f"CRITICAL THREAT: {model_name} flagged {attack_pct:.1f}% of recent traffic as malicious.\n"
        f"Suspected attacker: {top_attacker}\n"
        f"Primary target: {top_victim}"
    )
    subject = f"[NIDS] Critical threat detected ({model_name})"

    sent = []
    for name, fn in (
        ("slack", lambda: send_slack_alert(message)),
        ("webhook", lambda: send_webhook_alert(message)),
        ("email", lambda: send_email_alert(subject, message)),
        ("teams", lambda: send_teams_alert(message)),
        ("pagerduty", lambda: send_pagerduty_alert(message, subject)),
    ):
        try:
            if fn():
                sent.append(name)
        except Exception:
            continue
    return sent
