import pytest
from firewall_creation import firewall_rule_gen

def test_generate_firewall_rules_valid():
    ports = [80, 443]
    rules = firewall_rule_gen.generate_firewall_rules(ports)
    assert isinstance(rules, list)
    assert all('allow' in rule.lower() or 'accept' in rule.lower() for rule in rules)

def test_generate_firewall_rules_empty():
    ports = []
    rules = firewall_rule_gen.generate_firewall_rules(ports)
    assert rules == []

def test_generate_firewall_rules_invalid():
    ports = None
    with pytest.raises(TypeError):
        firewall_rule_gen.generate_firewall_rules(ports)
