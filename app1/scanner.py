import json
import nmap
import requests

def scan_target(target):
    print(f"[+] Scanning {target}...")
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sV')
    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port].get('version', '')
                results.append({
                    'host': host,
                    'port': port,
                    'service': service,
                    'version': version
                })
    return results

def run_scans():
    with open('config.json') as f:
        config = json.load(f)

    report_data = []
    for target in config['targets']:
        result = scan_target(target)
        report_data.append({
            'target': target,
            'findings': result
        })

    return report_data

if __name__ == "__main__":
    from report_generator import generate_report
    data = run_scans()
    generate_report(data)

try:
    with open("discovered_targets.json") as f:
        config["targets"] = json.load(f)
except FileNotFoundError:
    pass
