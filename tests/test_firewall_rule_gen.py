from firewall_creation import firewall_rule_gen
import pytest
import os

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

def test_load_vulnerability_report_file_not_found(monkeypatch):
    """Simulate missing report file."""
    missing_path = os.path.join(os.environ.get("TEMP", "/tmp"), "nonexistent_report.json")

    monkeypatch.setattr(firewall_rule_gen, "output_path", missing_path)

    with pytest.raises(SystemExit):
        firewall_rule_gen.load_vulnerability_report()

def test_load_vulnerability_report_invalid_json(tmp_path, monkeypatch):
    """Simulate corrupted JSON file."""
    # Create a temporary invalid JSON file
    bad_json_path = tmp_path / "nmap_scan_report.json"
    bad_json_path.write_text("{ invalid json ")

    monkeypatch.setattr(firewall_rule_gen, "output_path", str(bad_json_path))

    with pytest.raises(SystemExit):
        firewall_rule_gen.load_vulnerability_report()

def test_apply_firewall_rules_writes_correct_content(tmp_path):
    """Test that apply_firewall_rules writes the expected firewall rules."""
    dummy_rules = [
        "block drop in proto tcp from any to any port 80",
        "block return in proto tcp from any to any port 443"
    ]

    pf_rules_file = tmp_path / "block_ports.conf"

    firewall_rule_gen.apply_firewall_rules(dummy_rules, pf_rules_file=str(pf_rules_file))

    assert pf_rules_file.exists()

    with open(pf_rules_file, "r", encoding="utf-8") as f:
        content = f.read()

    assert "# Auto-generated firewall rules" in content
    for rule in dummy_rules:
        assert rule in content

def test_generate_firewall_rules_empty():
    report = {"findings": []}
    rules = firewall_rule_gen.generate_firewall_rules(report)
    assert isinstance(rules, list)
    assert rules == []

def test_generate_firewall_rules_invalid():
    report = None
    with pytest.raises(AttributeError):
        firewall_rule_gen.generate_firewall_rules(report)
