import csv
import io
import requests
from datetime import datetime

TIMEOUT = 15

def _fetch_csv(url):
    """Fetch a URL and return (rows, error). rows is a list of field-lists with
    comment lines stripped. On failure rows is [] and error is a string."""
    try:
        resp = requests.get(url, timeout=TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as e:
        return [], f"{type(e).__name__}: {e}"
    data_lines = [ln for ln in resp.text.splitlines() if not ln.startswith("#")]
    reader = csv.reader(io.StringIO("\n".join(data_lines)), skipinitialspace=True)
    return list(reader), None

def get_malwarebazaar_samples(limit=10):
    rows, err = _fetch_csv("https://bazaar.abuse.ch/export/csv/recent/")
    if err:
        return [], err
    # Columns: first_seen,sha256,md5,sha1,reporter,file_name,file_type_guess,mime_type,signature,...
    samples = []
    for parts in rows:
        if len(parts) >= 9:
            samples.append({
                "first_seen": parts[0],
                "sha256": parts[1],
                "md5": parts[2],
                "sha1": parts[3],
                "file_name": parts[5],
                "file_type": parts[6],
                "signature": parts[8],
            })
        if len(samples) >= limit:
            break
    return samples, None

def get_feodotracker_ips(limit=10):
    rows, err = _fetch_csv("https://feodotracker.abuse.ch/downloads/ipblocklist.csv")
    if err:
        return [], err
    # Columns: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
    ips = []
    for parts in rows:
        if parts and parts[0].lower().startswith("first_seen"):
            continue
        if len(parts) >= 4:
            ips.append({
                "first_seen": parts[0],
                "ip": parts[1],
                "port": parts[2],
                "status": parts[3] if len(parts) > 3 else "unknown",
                "malware": parts[5] if len(parts) > 5 else "unknown",
            })
        if len(ips) >= limit:
            break
    return ips, None

def get_ssl_blacklist(limit=10):
    rows, err = _fetch_csv("https://sslbl.abuse.ch/blacklist/sslblacklist.csv")
    if err:
        return [], err
    # Columns: Listingdate,SHA1,Listingreason
    certs = []
    for parts in rows:
        if parts and parts[0].lower().startswith("listingdate"):
            continue
        if len(parts) >= 3:
            certs.append({
                "date": parts[0],
                "sha1": parts[1],
                "malware": parts[2],
            })
        if len(certs) >= limit:
            break
    return certs, None

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
File Name: {sample['file_name']}
File Type: {sample['file_type']}
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
    malware_samples, err = get_malwarebazaar_samples()
    print(err if err else f"Retrieved {len(malware_samples)} malware samples")

    print("Fetching Feodo Tracker C2 IPs...")
    feodo_ips, err = get_feodotracker_ips()
    print(err if err else f"Retrieved {len(feodo_ips)} C2 IPs")

    print("Fetching SSL Blacklist...")
    ssl_certs, err = get_ssl_blacklist()
    print(err if err else f"Retrieved {len(ssl_certs)} SSL certificates")

    report = generate_report(malware_samples, feodo_ips, ssl_certs)
    filename = f"threat_digest_{datetime.now().strftime('%Y%m%d')}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"\nReport saved to {filename}")
    print(report)

if __name__ == "__main__":
    main()