import json
import os
import platform
import tempfile

OUTPUT_PATH = os.path.join(tempfile.gettempdir(), "nmap_scan_report.json")
FIREWALL_RULES_FILE = os.path.join(tempfile.gettempdir(), "windows_firewall_rules.bat")

def load_vulnerability_report(path=OUTPUT_PATH):
    if not os.path.exists(path):
        raise FileNotFoundError("Nmap report not found")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def generate_windows_firewall_rules(report):
    tcp_data = report.get("scan", {}).get("tcp", {})
    if not isinstance(tcp_data, dict):
        print("No TCP data found in scan report.")
        return []
    rule_lines = []
    for port, port_data in tcp_data.items():
        svc = port_data.get("name", "unknown")
        cmd = (
            f"netsh advfirewall firewall add rule name=Block_{svc}_{port} "
            f"dir=in action=block protocol=TCP localport={port}"
        )
        rule_lines.append(cmd)
    return rule_lines

def save_rules_to_file(commands):
    with open(FIREWALL_RULES_FILE, "w", encoding="utf-8") as f:
        for cmd in commands:
            f.write(cmd + "\n")
    print(f"Saved firewall rules to: {FIREWALL_RULES_FILE}")
    return FIREWALL_RULES_FILE

if __name__ == '__main__':
    if platform.system() != 'Windows':
        raise EnvironmentError("This script is intended for Windows systems.")

    report = load_vulnerability_report()
    rules = generate_windows_firewall_rules(report)
    save_rules_to_file(rules)

