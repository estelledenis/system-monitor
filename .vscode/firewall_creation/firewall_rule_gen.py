import json
import subprocess

def load_vulnerability_report(report_file="nmap_scan_report.json"):
    """Loads the JSON vulnerability report generated by the Nmap scan."""
    try:
        with open(report_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print("Error: Vulnerability report not found. Run the scan first.")
        exit(1)
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in the report.")
        exit(1)

def generate_firewall_rules(report):
    """Generates macOS PF firewall rules based on detected vulnerabilities."""
    firewall_rules = []
    high_risk_ports = []
    
    for finding in report.get("findings", []):
        port = finding.get("Port Number")
        risk_level = finding.get("Risk Assessment", "Unknown")
        
        if "🔴 High" in risk_level:
            print(f"[!] High-risk detected on port {port}, blocking it.")
            firewall_rules.append(f"block drop in proto tcp from any to any port {port}")
            high_risk_ports.append(port)
    
    return firewall_rules, high_risk_ports

def apply_firewall_rules(firewall_rules, pf_rules_file="/etc/block_ports.conf"):
    """Applies the generated firewall rules using a separate PF rules file."""
    try:
        with open(pf_rules_file, "w", encoding="utf-8") as pf_conf:
            pf_conf.write("# Auto-generated firewall rules\n")
            for rule in firewall_rules:
                pf_conf.write(rule + "\n")
        
        print("[+] Loading firewall rules from", pf_rules_file)
        subprocess.run(f"sudo pfctl -f {pf_rules_file}", shell=True, check=True)
        # Removed unnecessary pfctl -e since PF is already enabled
        print("✅ Firewall rules applied successfully!")
    except Exception as e:
        print(f"Error applying firewall rules: {e}")

def main():
    print("[+] Loading vulnerability report...")
    report = load_vulnerability_report()
    
    print("[+] Generating firewall rules...")
    firewall_rules, high_risk_ports = generate_firewall_rules(report)
    
    if not firewall_rules:
        print("[+] No high-risk vulnerabilities found. No firewall rules needed.")
        return
    
    print("[+] Applying firewall rules...")
    apply_firewall_rules(firewall_rules)
    
    print("🔍 Blocked high-risk ports:", high_risk_ports)

if __name__ == "__main__":
    main()
