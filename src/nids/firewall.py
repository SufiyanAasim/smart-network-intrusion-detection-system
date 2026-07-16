"""Suggested firewall-block rules for a flagged source IP.

These are copy-paste *suggestions* only — this module never executes any
command, opens a socket, or changes any system state. It just formats the
rule text for common firewalls so an operator can review and apply it
themselves.

Kept free of Streamlit imports so it can be unit tested directly.
"""

import ipaddress


def is_blockable(ip):
    """True if `ip` is a valid address worth suggesting a block for.

    Loopback and unspecified addresses are excluded — blocking them is
    almost never intended and usually a sign of a misread capture.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_unspecified)


def block_rule_snippets(ip):
    """Return {firewall: command_string} block rules for `ip`.

    Returns an empty dict for addresses that shouldn't be blocked (see
    is_blockable), so callers can show nothing rather than a bogus rule.
    """
    if not is_blockable(ip):
        return {}

    return {
        "Linux (iptables)": f"sudo iptables -A INPUT -s {ip} -j DROP",
        "Linux (ufw)": f"sudo ufw deny from {ip}",
        "Linux (nftables)": f"sudo nft add rule inet filter input ip saddr {ip} drop",
        "Windows (netsh)": (
            'netsh advfirewall firewall add rule '
            f'name="NIDS block {ip}" dir=in action=block remoteip={ip}'
        ),
    }
