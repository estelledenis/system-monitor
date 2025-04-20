from firewall_creation import firewall_rule_gen
import pytest

def test_generate_firewall_rules_valid():
    report = {
        "findings": [
            {"Port Number": 80, "Risk Assessment": "🔴 High"},
            {"Port Number": 443, "Risk Assessment": "🟡 Medium"}
        ]
    }
    rules = firewall_rule_gen.generate_firewall_rules(report)
    assert isinstance(rules, list)
    assert any(isinstance(rule, str) and "port 80" in rule for rule in rules)



def test_generate_firewall_rules_empty():
    report = {"findings": []}
    rules = firewall_rule_gen.generate_firewall_rules(report)
    assert isinstance(rules, list)
    assert rules == []

def test_generate_firewall_rules_invalid():
    report = None
    with pytest.raises(AttributeError):
        firewall_rule_gen.generate_firewall_rules(report)
