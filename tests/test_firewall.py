from tests import setup_test_environment
setup_test_environment()

from firewall_creation import firewall_rule_gen_windows as fw

def test_generate_windows_firewall_rules():
    dummy_report = {
        "tcp": {
            80: {"state": "open", "name": "http"},
            443: {"state": "open", "name": "https"},
        }
    }
    rules = fw.generate_windows_firewall_rules(dummy_report)
    assert isinstance(rules, list)
    assert any("port=80" in rule for rule in rules)
    assert any("port=443" in rule for rule in rules)
