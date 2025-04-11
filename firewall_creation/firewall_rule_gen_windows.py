import json
import os
import platform
import subprocess
import tempfile

OUTPUT_PATH = os.path.join(tempfile.gettempdir(), "nmap_scan_report.json")

def load_vulnerability_report(path=OUTPUT_PATH):
    if not os.path.exists(path):
        raise FileNotFoundError("Nmap report not found")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def generate_windows_firewall_rules(report):
    port_entries = []
    scan_data = report.get("scan", {})
    for host, details in scan_data.items():
        if isinstance(details, list):
            print(f"Skipping unexpected list format for host {host}")
            continue
        tcp_data = details.get("tcp", {})
        if not isinstance(tcp_data, dict):
            print(f"No TCP data found for host {host}")
            continue
        for port, port_data in tcp_data.items():
            svc = port_data.get("name", "unknown")
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=Block_{svc}_{port}",
                f"dir=in", f"action=block",
                f"protocol=TCP", f"localport={port}"
            ]
            port_entries.append(cmd)
    return port_entries

def apply_firewall_rules(commands):
    for cmd in commands:
        print("Applying:", " ".join(cmd))
        subprocess.run(cmd, check=True)

if __name__ == '__main__':
    if platform.system() != 'Windows':
        raise EnvironmentError("This script is intended for Windows systems.")

    report = load_vulnerability_report()
    rules = generate_windows_firewall_rules(report)
    apply_firewall_rules(rules)
