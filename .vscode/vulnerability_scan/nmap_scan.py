import nmap
import json
import datetime

def scan_localhost():
    nm = nmap.PortScanner()
    print("Scanning your computer for security risks... Please wait.")
    nm.scan('127.0.0.1', arguments='-sV --script vuln')
    
    report = {
        "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host": "Your Computer (127.0.0.1)",
        "explanation": {
            "Port Number": "The specific network port that was scanned.",
            "Protocol": "The type of communication protocol used (e.g., TCP or UDP).",
            "Service Detected": "The name of the service running on the port, if detected.",
            "Software Version": "The version of the service software, if detected.",
            "Risk Assessment": "An evaluation of the security risk posed by this service:",
            "Risk Levels": {
                "🟢 Low": "No immediate threat. Generally safe.",
                "🟡 Medium": "Potential risk. Further investigation is recommended.",
                "🔴 High": "Urgent! Immediate action is recommended to secure this service."
            },
            "Vulnerabilities": "Known security issues associated with the detected service, if any."
        },
        "findings": []
    }
    
    risk_levels = {"Low": "🟢 Low - No immediate threat.",
                   "Medium": "🟡 Medium - Potential risk, investigate further.",
                   "High": "🔴 High - Urgent! Immediate action recommended."}
    
    for proto in nm['127.0.0.1'].all_protocols():
        ports = nm['127.0.0.1'][proto].keys()
        for port in ports:
            service = nm['127.0.0.1'][proto][port]
            risk = "Low"
            
            if "vulners" in service:
                vulns = service["vulners"]
                for vuln in vulns:
                    if 'CVSS' in vuln and float(vuln['CVSS']) >= 7:
                        risk = "High"
                    else:
                        risk = "Medium"
            
            finding = {
                "Port Number": port,
                "Protocol": proto.upper(),
                "Service Detected": service.get("name", "Unknown") or "Unknown",
                "Software Version": service.get("version", "Unknown") or "Unknown",
                "Risk Assessment": risk_levels[risk]
            }
            
            if "vulners" in service:
                finding["Vulnerabilities"] = []
                for vuln in service["vulners"]:
                    finding["Vulnerabilities"].append({
                        "CVE ID": vuln.get("id", "Unknown") or "Unknown",
                        "Description": vuln.get("description", "No description available") or "Unknown",
                        "Severity": risk_levels[risk]
                    })
            
            report["findings"].append(finding)
    
    with open("nmap_scan_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    
    generate_html_report(report)
    
    print("✅ Scan complete! Reports have been saved as 'nmap_scan_report.json' and 'nmap_scan_report.html'.")
    print("🔍 Open the HTML report for a user-friendly view of potential risks and suggested actions.")

def generate_html_report(report):
    html_content = f"""
    <html>
    <head>
        <title>Security Scan Report</title>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
            th {{ background-color: #f4f4f4; }}
        </style>
    </head>
    <body>
        <h1>Security Scan Report</h1>
        <p><strong>Scan Time:</strong> {report['scan_time']}</p>
        <p><strong>Scanned Host:</strong> {report['host']}</p>
        <h2>Understanding This Report</h2>
        <ul>
            <li><strong>Port Number:</strong> {report['explanation']['Port Number']}</li>
            <li><strong>Protocol:</strong> {report['explanation']['Protocol']}</li>
            <li><strong>Service Detected:</strong> {report['explanation']['Service Detected']}</li>
            <li><strong>Software Version:</strong> {report['explanation']['Software Version']}</li>
            <li><strong>Risk Assessment:</strong> {report['explanation']['Risk Assessment']}</li>
            <li><strong>Risk Levels:</strong>
                <ul>
                    <li>{report['explanation']['Risk Levels']['🟢 Low']}</li>
                    <li>{report['explanation']['Risk Levels']['🟡 Medium']}</li>
                    <li>{report['explanation']['Risk Levels']['🔴 High']}</li>
                </ul>
            </li>
        </ul>
        <h2>Findings</h2>
        <table>
            <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>Version</th>
                <th>Risk Level</th>
                <th>Vulnerabilities</th>
            </tr>
    """
    
    for finding in report["findings"]:
        vulns = "<br>".join([f"{v['CVE ID']}: {v['Description']} ({v['Severity']})" for v in finding.get("Vulnerabilities", [])]) or "None"
        html_content += f"""
            <tr>
                <td>{finding['Port Number']}</td>
                <td>{finding['Protocol']}</td>
                <td>{finding['Service Detected']}</td>
                <td>{finding['Software Version']}</td>
                <td>{finding['Risk Assessment']}</td>
                <td>{vulns}</td>
            </tr>
        """
    
    html_content += """
        </table>
    </body>
    </html>
    """
    
    with open("nmap_scan_report.html", "w", encoding="utf-8") as f:
        f.write(html_content)

if __name__ == "__main__":
    scan_localhost()
