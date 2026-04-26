import requests
from datetime import datetime

def get_malwarebazaar_samples():
    url = "https://bazaar.abuse.ch/export/csv/recent/"
    response = requests.get(url)
    lines = response.text.splitlines()
    samples = []
    for line in lines:
        if line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) >= 9:
            samples.append({
                "first_seen": parts[0].strip('"'),
                "sha256": parts[1].strip('"'),
                "md5": parts[2].strip('"'),
                "sha1": parts[3].strip('"'),
                "file_type": parts[4].strip('"'),
                "file_name": parts[6].strip('"') if len(parts) > 6 else "Unknown",
                "signature": parts[7].strip('"') if len(parts) > 7 else "Unknown"
            })
        if len(samples) >= 10:
            break
    return samples

def get_feodotracker_ips():
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
    response = requests.get(url)
    lines = response.text.splitlines()
    ips = []
    for line in lines:
        if line.startswith("#"):
            continue
        if line.startswith("first_seen"):
            continue
        parts = line.split(",")
        if len(parts) >= 4:
            ips.append({
                "first_seen": parts[0].strip('"'),
                "ip": parts[1].strip('"'),
                "port": parts[2].strip('"'),
                "malware": parts[3].strip('"')
            })
        if len(ips) >= 10:
            break
    return ips

def get_ssl_blacklist():
    url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
    response = requests.get(url)
    lines = response.text.splitlines()
    certs = []
    for line in lines:
        if line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) >= 3:
            certs.append({
                "date": parts[0].strip('"'),
                "sha1": parts[1].strip('"'),
                "malware": parts[2].strip('"')
            })
        if len(certs) >= 10:
            break
    return certs

def generate_report(malware_samples, feodo_ips, ssl_certs):
    report_date = datetime.now().strftime("%Y-%m-%d %H:%M")
    report = f"""
DAILY THREAT INTELLIGENCE DIGEST
Generated: {report_date}
{'='*60}

MALWAREBAZAAR - RECENT MALWARE SAMPLES
{'='*60}
"""
    for sample in malware_samples:
        report += f"""
First Seen: {sample['first_seen']}
SHA256: {sample['sha256']}
MD5: {sample['md5']}
SHA1: {sample['sha1']}
File Type: {sample['file_type']}
File Name: {sample['file_name']}
Signature: {sample['signature']}
{'-'*40}
"""

    report += f"""

FEODOTRACKER - BOTNET C2 IP BLOCKLIST
{'='*60}
"""
    if feodo_ips:
        for ip in feodo_ips:
            report += f"""
First Seen: {ip['first_seen']}
IP: {ip['ip']}
Port: {ip['port']}
Malware: {ip['malware']}
{'-'*40}
"""
    else:
        report += "\nNo C2 IPs retrieved.\n"

    report += f"""

SSL BLACKLIST - MALICIOUS SSL CERTIFICATES
{'='*60}
"""
    if ssl_certs:
        for cert in ssl_certs:
            report += f"""
Date: {cert['date']}
SHA1: {cert['sha1']}
Malware: {cert['malware']}
{'-'*40}
"""
    else:
        report += "\nNo SSL certificates retrieved.\n"

    return report

def main():
    print("Fetching MalwareBazaar samples...")
    malware_samples = get_malwarebazaar_samples()
    print(f"Retrieved {len(malware_samples)} malware samples")

    print("Fetching Feodo Tracker C2 IPs...")
    feodo_ips = get_feodotracker_ips()
    print(f"Retrieved {len(feodo_ips)} C2 IPs")

    print("Fetching SSL Blacklist...")
    ssl_certs = get_ssl_blacklist()
    print(f"Retrieved {len(ssl_certs)} SSL certificates")

    report = generate_report(malware_samples, feodo_ips, ssl_certs)

    filename = f"threat_digest_{datetime.now().strftime('%Y%m%d')}.txt"
    with open(filename, "w") as f:
        f.write(report)

    print(f"\nReport saved to {filename}")
    print(report)

if __name__ == "__main__":
    main()