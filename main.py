import ipaddress
import socket
from urllib.parse import urlparse
import nmap
import re
import requests
import urllib3
from flask import Flask, jsonify, render_template, request

import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
WEIGHTS = {"high": 30, "medium": 15, "low": 5}

HEADER_CVSS_MAP = {
    'content-security-policy': 4.3,    
    'strict-transport-security': 3.7,  
    'x-frame-options': 4.3,            
    'x-content-type-options': 4.3      
}


def is_authorized(host: str) -> bool:
    return True


def sprint(name, status, severity, finding, fix, port="N/A"):
    return {"name": name, "status": status, "severity": severity,
            "finding": finding, "fix": fix, "port": port}


def evaluate_security_headers(url, port_str):
    try:
        resp = requests.get(url, timeout=10, verify=False, allow_redirects=False)
        headers = {k.lower(): v for k, v in resp.headers.items()}
    except requests.RequestException as e:
        return sprint("Security Headers", "vulnerable", "high", 
                      f"Failed to fetch headers: {type(e).__name__} | CVE: None | CVSS: 0.0", "Verify target is reachable via HTTP/HTTPS.", port=port_str)

    missing = []
    highest_cvss = 0.0
    
    for header, cvss in HEADER_CVSS_MAP.items():
        if header not in headers:
            missing.append(header)
            if cvss > highest_cvss:
                highest_cvss = cvss

    if missing:
        severity = "medium" if highest_cvss >= 4.0 else "low"
        return sprint("Security Headers", "vulnerable", severity, 
                      f"Missing: {', '.join(missing)} | CVE: HTTP-Misconfig | CVSS: {highest_cvss}", 
                      "Configure missing HTTP headers on the server.", port=port_str)
                      
    return sprint("Security Headers", "secure", None, "All headers present. | CVE: None | CVSS: 0.0", "", port=port_str)


def extract_cve_and_cvss(output):
    cve_id = "None"
    cvss_score = 0.0
    
    if isinstance(output, str):
        cve_match = re.search(r'(?i)(CVE-\d{4}-\d+)', output)
        if cve_match:
            cve_id = cve_match.group(1).upper()
            
        cvss_match = re.search(r'(?i)cvss[^0-9]*([0-9]+\.[0-9]+)', output)
        if not cvss_match:
            cvss_match = re.search(r'(?i)CVE-\d{4}-\d+[^\d]+([0-9]+\.[0-9]+)', output)
            
        if cvss_match:
            try:
                cvss_score = float(cvss_match.group(1))
            except ValueError:
                pass
                
    return cve_id, cvss_score


def scan_lab_target(ip_address, target_ports, scan_type="T4"):
    nm = nmap.PortScanner()
    timing_flag = "-T5" if scan_type == "T5" else "-T4"
    print(f"[*] Initiating {timing_flag} scan on: {ip_address}:{target_ports}")

    # FIX: Strict Nmap arguments without quotes to prevent python-nmap shlex crashes
    if scan_type == "T4":
        scan_args = '-sV -Pn -T4 --host-timeout 40s --script vuln'
    else:
        scan_args = '-sV -Pn -T5 --script vuln'

    try:
        nm.scan(ip_address, target_ports, scan_args)
    except Exception as e:
        print(f"[!] Nmap execution error: {e}")
        return [], []

    found_vulns = []
    open_ports = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                port_data = nm[host][proto][port]
                
                if 'open' in port_data.get('state', ''):
                    service_name = port_data.get('name', 'unknown')
                    product = port_data.get('product', '')
                    version = port_data.get('version', '')
                    
                    display_version = f"{product} {version}".strip()
                    is_wrapped = False
                    
                    if 'tcpwrapped' in service_name or 'tcpwrapped' in display_version or not display_version:
                        is_wrapped = True
                        display_version = "tcpwrapped (Security Plus: Version Obscured)"
                    
                    open_ports.append({
                        "port": str(port),
                        "service": service_name.upper(),
                        "version": display_version,
                        "is_secure_wrapped": is_wrapped
                    })

                scripts = port_data.get('script', {})
                for script_name, output in scripts.items():
                    cve, cvss = extract_cve_and_cvss(output)
                    found_vulns.append({
                        "host": host,
                        "port": str(port),
                        "finding": script_name,
                        "cve_id": cve,
                        "raw_cvss": cvss
                    })
                    
    return found_vulns, open_ports


def calculate_business_risk(vulnerability, asset_metadata):
    base_cvss = vulnerability.get('raw_cvss', 0.0)
    exploit_factor = 1.5 if vulnerability.get('known_exploit') else 1.0
    criticality = asset_metadata.get('business_value_score', 1.0) 
    exposure = 1.5 if asset_metadata.get('internet_facing') else 1.0
    
    business_risk = (base_cvss * exploit_factor) * criticality * exposure
    vulnerability['business_risk_score'] = round(business_risk, 2)
    return vulnerability


def run_scan(url, scan_type):
    parsed = urlparse(url)
    target_host = parsed.hostname or url.split('://')[-1].split(':')[0]
    target_ports = str(parsed.port) if parsed.port else "80,443"
    
    lab_metadata = {
        "business_value_score": 1.0,  
        "internet_facing": False,    
        "known_exploit": False       
    }
    
    sprints = []
    
    header_sprint = evaluate_security_headers(url, target_ports)
    if header_sprint:
        sprints.append(header_sprint)
    
    raw_vulns, open_ports = scan_lab_target(target_host, target_ports, scan_type)
    
    if not raw_vulns:
        sprints.append(sprint("Nmap Scan", "secure", None, "No network vulnerabilities found. | CVE: None | CVSS: 0.0", "", port=target_ports))
    else:
        scored_vulns = [calculate_business_risk(v, lab_metadata) for v in raw_vulns]
        scored_vulns.sort(key=lambda x: x['business_risk_score'], reverse=True)
        
        for vuln in scored_vulns:
            risk = vuln['business_risk_score']
            severity = "high" if risk >= 7.0 else "medium" if risk >= 4.0 else "low"
            
            sprints.append(sprint(
                name=vuln['finding'][:25],
                status="vulnerable",
                severity=severity,
                finding=f"Port: {vuln['port']} | CVE: {vuln['cve_id']} | CVSS: {vuln['raw_cvss']}",
                fix="Review Nmap script output and apply patches.",
                port=vuln['port']
            ))
            
    return sprints, open_ports


def build_response(url, sprints, open_ports):
    score = min(100, sum(WEIGHTS.get(s.get("severity"), 0) for s in sprints if s.get("severity")))
    level = "critical" if score >= 60 else "high" if score >= 35 else \
            "moderate" if score >= 15 else "low"
            
    return {"target": url, "sprints": sprints, "open_ports": open_ports,
            "risk": {"score": score, "level": level},
            "xp": max(0, 100 - score)}


@app.route("/")
def index():
    return render_template("index_2.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    scan_type = data.get("scan_type", "T4") 
    
    if not data.get("authorized"):
        return jsonify(error="Confirm you are authorized to test this target."), 400
    
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return jsonify(error="Enter a full URL, e.g. http://127.0.0.1:3000"), 400
        
    if not is_authorized(parsed.hostname):
        return jsonify(error="Target not allowed."), 403
        
    try:
        sprints, open_ports = run_scan(url, scan_type)
        return jsonify(build_response(url, sprints, open_ports))
    except Exception as e:
        return jsonify(error=f"Scan failed: {type(e).__name__} - {str(e)}"), 502


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)