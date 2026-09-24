import nmap
import re
import json

def extract_cvss_from_output(output):
    """
    Parses Nmap vulnerability script output to find a CVSS score.
    Returns a float (e.g., 7.5) if found, otherwise returns 0.0.
    """
    if not isinstance(output, str):
        return 0.0
        
    match = re.search(r'(?i)cvss[^0-9]*([0-9]+\.[0-9]+)', output)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return 0.0
            
    return 0.0

def scan_lab_target(ip_address):
    """
    Scans a local, authorized lab environment for vulnerabilities.
    """
    nm = nmap.PortScanner()
    
    # Focusing on standard web ports for a local test environment
    print(f"[*] Initiating scan on local target: {ip_address}")
    nm.scan(ip_address, '80,443', '-sV --script vuln')
    
    found_vulns = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                # Extract script outputs
                scripts = nm[host][proto][port].get('script', {})
                for script_name, output in scripts.items():
                    found_vulns.append({
                        "host": host,
                        "port": port,
                        "finding": script_name,
                        "raw_cvss": extract_cvss_from_output(output)
                    })
    return found_vulns

def calculate_business_risk(vulnerability, asset_metadata):
    """
    Calculates business risk based on CVSS, exploitability, criticality, and exposure.
    """
    base_cvss = vulnerability.get('raw_cvss', 0.0)
    
    # environmental context
    exploit_factor = 1.5 if vulnerability.get('known_exploit') else 1.0
    criticality = asset_metadata.get('business_value_score', 1.0) 
    exposure = 1.5 if asset_metadata.get('internet_facing') else 1.0
    
    # Calculate and cap the risk score
    business_risk = (base_cvss * exploit_factor) * criticality * exposure
    vulnerability['business_risk_score'] = round(business_risk, 2)
    
    return vulnerability

def generate_remediation_plan(scored_vulnerabilities, weekly_capacity=5):
    """
    Chunks vulnerabilities into weekly sprint batches based on risk.
    """
    sorted_vulns = sorted(
        scored_vulnerabilities, 
        key=lambda x: x['business_risk_score'], 
        reverse=True
    )
    
    sprint_plan = {}
    sprint_number = 1
    
    for i in range(0, len(sorted_vulns), weekly_capacity):
        sprint_plan[f"Sprint_{sprint_number}"] = sorted_vulns[i:i + weekly_capacity]
        sprint_number += 1
        
    return sprint_plan

 
if __name__ == "__main__": 
    LOCAL_TARGET = "54.235.77.118" 
    
    lab_metadata = {
        "business_value_score": 1.0,  
        "internet_facing": False,    
        "known_exploit": False       
    }
    
    # 1. Scan
    raw_vulnerabilities = scan_lab_target(LOCAL_TARGET)
    print(f"[*] Scan complete. Discovered {len(raw_vulnerabilities)} potential findings.")
    
    # 2. Score
    scored_vulnerabilities = []
    for vuln in raw_vulnerabilities:
        scored = calculate_business_risk(vuln, lab_metadata)
        scored_vulnerabilities.append(scored)
        
    # 3. Plan
    if scored_vulnerabilities:
        print("[*] Generating Remediation Plan...")
        final_plan = generate_remediation_plan(scored_vulnerabilities, weekly_capacity=2)
        print(json.dumps(final_plan, indent=2))
    else:
        print("[*] No vulnerabilities found. No remediation plan required.")