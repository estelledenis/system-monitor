import pytest
import tempfile
import os
from firewall_creation import firewall_rule_gen_windows as fw

def test_generate_windows_firewall_rules():
    dummy_report = {
        "tcp": {
            80: {"state": "open", "name": "http"},
            445: {"state": "open", "name": "microsoft-ds"}
        }
    }
    rules = fw.generate_windows_firewall_rules(dummy_report)
    assert any("port=80" in rule for rule in rules)
    assert any("port=445" in rule for rule in rules)

def test_save_rules_to_batch():
    dummy_rules = ["netsh advfirewall firewall add rule name=Test port=80 protocol=TCP action=block"]
    temp_path = tempfile.NamedTemporaryFile(delete=False).name
    fw.save_rules_to_batch(dummy_rules, temp_path)
    with open(temp_path, 'r') as f:
        content = f.read()
    assert "netsh advfirewall" in content
    os.remove(temp_path)
