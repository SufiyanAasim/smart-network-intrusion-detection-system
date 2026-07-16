from nids import firewall


def test_is_blockable():
    assert firewall.is_blockable("8.8.8.8") is True
    assert firewall.is_blockable("10.0.0.1") is True
    assert firewall.is_blockable("127.0.0.1") is False
    assert firewall.is_blockable("0.0.0.0") is False
    assert firewall.is_blockable("not-an-ip") is False


def test_block_rule_snippets_contains_ip_and_tools():
    rules = firewall.block_rule_snippets("8.8.8.8")
    assert "Linux (iptables)" in rules
    assert "Windows (netsh)" in rules
    for command in rules.values():
        assert "8.8.8.8" in command


def test_block_rule_snippets_empty_for_unblockable():
    assert firewall.block_rule_snippets("127.0.0.1") == {}
    assert firewall.block_rule_snippets("bad") == {}
