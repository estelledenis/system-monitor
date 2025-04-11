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
    for host, details in report.get("scan", {}).items():
        for port_proto, port_data in details.get("tcp", {}).items():
            port = int(port_proto)
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
