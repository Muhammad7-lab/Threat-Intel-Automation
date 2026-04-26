import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import requests
import webbrowser
from datetime import datetime
from config import VT_API_KEY

BG = "#0d1117"
PANEL = "#161b22"
ACCENT = "#238636"
ACCENT_HOVER = "#2ea043"
TEXT = "#c9d1d9"
MUTED = "#8b949e"
BORDER = "#30363d"
RED = "#f85149"
YELLOW = "#e3b341"
GREEN = "#3fb950"
BLUE = "#58a6ff"

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

def lookup_virustotal(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        name = data.get("data", {}).get("attributes", {}).get("meaningful_name", "Unknown")
        return {
            "name": name,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "clean": stats.get("undetected", 0),
            "total": sum(stats.values())
        }
    elif response.status_code == 404:
        return {"error": "Hash not found in VirusTotal"}
    elif response.status_code == 429:
        return {"error": "Rate limit reached — wait 1 minute and try again"}
    else:
        return {"error": f"Error {response.status_code}"}

class ThreatIntelApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Threat Intelligence Automation")
        self.root.geometry("1100x750")
        self.root.configure(bg=BG)
        self.root.resizable(True, True)
        self.report_content = ""
        self.fetched_samples = []

        self.build_header()
        self.build_controls()
        self.build_vt_lookup()
        self.build_output()
        self.build_statusbar()

    def build_header(self):
        header = tk.Frame(self.root, bg=PANEL, pady=12)
        header.pack(fill="x")

        tk.Label(
            header,
            text="⚡ THREAT INTELLIGENCE AUTOMATION",
            font=("Consolas", 16, "bold"),
            bg=PANEL,
            fg=TEXT
        ).pack(side="left", padx=20)

        self.timestamp_label = tk.Label(
            header,
            text="",
            font=("Consolas", 10),
            bg=PANEL,
            fg=MUTED
        )
        self.timestamp_label.pack(side="right", padx=20)

    def build_controls(self):
        control_frame = tk.Frame(self.root, bg=BG, pady=10)
        control_frame.pack(fill="x", padx=20)

        tk.Label(
            control_frame,
            text="SELECT SOURCES",
            font=("Consolas", 9, "bold"),
            bg=BG,
            fg=MUTED
        ).pack(anchor="w", pady=(0, 5))

        checkbox_frame = tk.Frame(control_frame, bg=BG)
        checkbox_frame.pack(fill="x")

        self.var_malware = tk.BooleanVar(value=True)
        self.var_feodo = tk.BooleanVar(value=True)
        self.var_ssl = tk.BooleanVar(value=True)

        for text, var in [
            ("MalwareBazaar", self.var_malware),
            ("Feodo Tracker C2 IPs", self.var_feodo),
            ("SSL Blacklist", self.var_ssl)
        ]:
            cb = tk.Checkbutton(
                checkbox_frame,
                text=text,
                variable=var,
                bg=BG,
                fg=TEXT,
                selectcolor=PANEL,
                activebackground=BG,
                activeforeground=TEXT,
                font=("Consolas", 10),
                cursor="hand2"
            )
            cb.pack(side="left", padx=(0, 20))

        btn_frame = tk.Frame(control_frame, bg=BG)
        btn_frame.pack(fill="x", pady=10)

        self.run_btn = tk.Button(
            btn_frame,
            text="RUN THREAT INTEL FETCH",
            font=("Consolas", 11, "bold"),
            bg=ACCENT,
            fg="white",
            activebackground=ACCENT_HOVER,
            activeforeground="white",
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2",
            command=self.run_fetch
        )
        self.run_btn.pack(side="left")

        self.clear_btn = tk.Button(
            btn_frame,
            text="CLEAR",
            font=("Consolas", 11),
            bg=PANEL,
            fg=MUTED,
            activebackground=BORDER,
            activeforeground=TEXT,
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2",
            command=self.clear_output
        )
        self.clear_btn.pack(side="left", padx=10)

        self.save_btn = tk.Button(
            btn_frame,
            text="SAVE REPORT",
            font=("Consolas", 11),
            bg=PANEL,
            fg=MUTED,
            activebackground=BORDER,
            activeforeground=TEXT,
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2",
            command=self.save_report
        )
        self.save_btn.pack(side="left")

        self.html_btn = tk.Button(
            btn_frame,
            text="EXPORT HTML",
            font=("Consolas", 11),
            bg=PANEL,
            fg=BLUE,
            activebackground=BORDER,
            activeforeground=BLUE,
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2",
            command=self.export_html
        )
        self.html_btn.pack(side="left", padx=10)

    def build_vt_lookup(self):
        vt_frame = tk.Frame(self.root, bg=BG, pady=5)
        vt_frame.pack(fill="x", padx=20)

        tk.Label(
            vt_frame,
            text="VIRUSTOTAL HASH LOOKUP",
            font=("Consolas", 9, "bold"),
            bg=BG,
            fg=MUTED
        ).pack(anchor="w", pady=(0, 5))

        input_row = tk.Frame(vt_frame, bg=BG)
        input_row.pack(fill="x")

        self.hash_entry = tk.Entry(
            input_row,
            font=("Consolas", 10),
            bg=PANEL,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            width=70
        )
        self.hash_entry.pack(side="left", ipady=6, padx=(0, 10))
        self.hash_entry.insert(0, "Enter SHA256 or MD5 hash...")
        self.hash_entry.bind("<FocusIn>", lambda e: self.hash_entry.delete(0, "end") if self.hash_entry.get() == "Enter SHA256 or MD5 hash..." else None)

        self.vt_btn = tk.Button(
            input_row,
            text="LOOKUP",
            font=("Consolas", 10, "bold"),
            bg="#1f6feb",
            fg="white",
            activebackground="#388bfd",
            activeforeground="white",
            relief="flat",
            padx=15,
            pady=6,
            cursor="hand2",
            command=self.run_vt_lookup
        )
        self.vt_btn.pack(side="left")

    def build_output(self):
        output_frame = tk.Frame(self.root, bg=BG)
        output_frame.pack(fill="both", expand=True, padx=20, pady=(10, 10))

        tk.Label(
            output_frame,
            text="OUTPUT",
            font=("Consolas", 9, "bold"),
            bg=BG,
            fg=MUTED
        ).pack(anchor="w", pady=(0, 5))

        self.output = scrolledtext.ScrolledText(
            output_frame,
            font=("Consolas", 10),
            bg=PANEL,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            padx=15,
            pady=15,
            wrap="word",
            state="disabled"
        )
        self.output.pack(fill="both", expand=True)

        self.output.tag_config("header", foreground=ACCENT, font=("Consolas", 10, "bold"))
        self.output.tag_config("section", foreground=YELLOW, font=("Consolas", 10, "bold"))
        self.output.tag_config("key", foreground=MUTED)
        self.output.tag_config("value", foreground=TEXT)
        self.output.tag_config("online", foreground=RED, font=("Consolas", 10, "bold"))
        self.output.tag_config("divider", foreground=BORDER)
        self.output.tag_config("vt_clean", foreground=GREEN, font=("Consolas", 10, "bold"))
        self.output.tag_config("vt_malicious", foreground=RED, font=("Consolas", 10, "bold"))
        self.output.tag_config("vt_header", foreground=BLUE, font=("Consolas", 10, "bold"))

    def build_statusbar(self):
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            font=("Consolas", 9),
            bg=PANEL,
            fg=MUTED,
            anchor="w",
            padx=20,
            pady=5
        )
        status_bar.pack(fill="x", side="bottom")

    def write(self, text, tag=None):
        self.output.configure(state="normal")
        if tag:
            self.output.insert("end", text, tag)
        else:
            self.output.insert("end", text)
        self.output.configure(state="disabled")
        self.output.see("end")

    def clear_output(self):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")
        self.report_content = ""
        self.status_var.set("Cleared")

    def save_report(self):
        if not self.report_content:
            self.status_var.set("Nothing to save — run a fetch first")
            return
        filename = f"threat_digest_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
        with open(filename, "w") as f:
            f.write(self.report_content)
        self.status_var.set(f"Report saved to {filename}")

    def export_html(self):
        if not self.report_content:
            self.status_var.set("Nothing to export — run a fetch first")
            return
        filename = f"threat_digest_{datetime.now().strftime('%Y%m%d_%H%M')}.html"
        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Threat Intelligence Digest</title>
<style>
  body {{ background: #0d1117; color: #c9d1d9; font-family: Consolas, monospace; padding: 30px; }}
  h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
  h2 {{ color: #e3b341; margin-top: 30px; }}
  .entry {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; margin: 10px 0; }}
  .key {{ color: #8b949e; }}
  .value {{ color: #c9d1d9; }}
  .online {{ color: #f85149; font-weight: bold; }}
  .clean {{ color: #3fb950; font-weight: bold; }}
  .malicious {{ color: #f85149; font-weight: bold; }}
  .timestamp {{ color: #8b949e; font-size: 12px; }}
</style>
</head>
<body>
<h1>Threat Intelligence Digest</h1>
<p class="timestamp">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
"""
        if self.fetched_samples:
            html += "<h2>MalwareBazaar — Recent Malware Samples</h2>"
            for s in self.fetched_samples:
                html += f"""<div class="entry">
<span class="key">First Seen:</span> <span class="value">{s['first_seen']}</span><br>
<span class="key">SHA256:</span> <span class="value">{s['sha256']}</span><br>
<span class="key">MD5:</span> <span class="value">{s['md5']}</span><br>
<span class="key">File Type:</span> <span class="value">{s['file_type']}</span><br>
<span class="key">Signature:</span> <span class="value">{s['signature']}</span>
</div>"""

        html += "</body></html>"

        with open(filename, "w") as f:
            f.write(html)

        webbrowser.open(filename)
        self.status_var.set(f"HTML report exported and opened: {filename}")

    def run_vt_lookup(self):
        hash_value = self.hash_entry.get().strip()
        if not hash_value or hash_value == "Enter SHA256 or MD5 hash...":
            self.status_var.set("Enter a hash to look up")
            return
        self.vt_btn.configure(state="disabled", text="LOOKING UP...")
        self.status_var.set(f"Querying VirusTotal for {hash_value[:20]}...")
        thread = threading.Thread(target=self.fetch_vt, args=(hash_value,))
        thread.daemon = True
        thread.start()

    def fetch_vt(self, hash_value):
        result = lookup_virustotal(hash_value)
        self.write("\n", )
        self.write("━"*60 + "\n", "divider")
        self.write(" VIRUSTOTAL LOOKUP RESULT\n", "vt_header")
        self.write("━"*60 + "\n", "divider")
        if "error" in result:
            self.write(f"\n  Error: {result['error']}\n", "online")
        else:
            self.write(f"\n  Hash:       ", "key")
            self.write(f"{hash_value}\n", "value")
            self.write(f"  Name:       ", "key")
            self.write(f"{result['name']}\n", "value")
            self.write(f"  Malicious:  ", "key")
            tag = "vt_malicious" if result['malicious'] > 0 else "vt_clean"
            self.write(f"{result['malicious']}/{result['total']} engines\n", tag)
            self.write(f"  Suspicious: ", "key")
            self.write(f"{result['suspicious']}\n", "value")
            self.write(f"  Clean:      ", "key")
            self.write(f"{result['clean']}\n", "vt_clean")
        self.write("━"*60 + "\n", "divider")
        self.vt_btn.configure(state="normal", text="LOOKUP")
        self.status_var.set("VirusTotal lookup complete")

    def run_fetch(self):
        self.clear_output()
        self.run_btn.configure(state="disabled", text="FETCHING...")
        self.status_var.set("Fetching threat intelligence...")
        thread = threading.Thread(target=self.fetch_data)
        thread.daemon = True
        thread.start()

    def fetch_data(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.timestamp_label.configure(text=f"Last run: {now}")
        self.report_content = f"DAILY THREAT INTELLIGENCE DIGEST\nGenerated: {now}\n\n"
        self.fetched_samples = []

        if self.var_malware.get():
            self.status_var.set("Fetching MalwareBazaar...")
            self.write("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", "divider")
            self.write(" MALWAREBAZAAR — RECENT MALWARE SAMPLES\n", "section")
            self.write("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", "divider")
            samples = get_malwarebazaar_samples()
            self.fetched_samples = samples
            self.report_content += "MALWAREBAZAAR\n" + "="*60 + "\n"
            for s in samples:
                self.write(f"\n  First Seen:  ", "key")
                self.write(f"{s['first_seen']}\n", "value")
                self.write(f"  SHA256:      ", "key")
                self.write(f"{s['sha256']}\n", "value")
                self.write(f"  MD5:         ", "key")
                self.write(f"{s['md5']}\n", "value")
                self.write(f"  File Type:   ", "key")
                self.write(f"{s['file_type']}\n", "value")
                self.write(f"  File Name:   ", "key")
                self.write(f"{s['file_name']}\n", "value")
                self.write(f"  Signature:   ", "key")
                self.write(f"{s['signature']}\n", "value")
                self.write("  " + "─"*56 + "\n", "divider")
                self.report_content += f"SHA256: {s['sha256']}\nMD5: {s['md5']}\n\n"

        if self.var_feodo.get():
            self.status_var.set("Fetching Feodo Tracker C2 IPs...")
            self.write("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", "divider")
            self.write(" FEODO TRACKER — BOTNET C2 IP BLOCKLIST\n", "section")
            self.write("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", "divider")
            ips = get_feodotracker_ips()
            self.report_content += "\nFEODO TRACKER\n" + "="*60 + "\n"
            for ip in ips:
                self.write(f"\n  First Seen:  ", "key")
                self.write(f"{ip['first_seen']}\n", "value")
                self.write(f"  IP:          ", "key")
                self.write(f"{ip['ip']}\n", "value")
                self.write(f"  Port:        ", "key")
                self.write(f"{ip['port']}\n", "value")
                self.write(f"  Status:      ", "key")
                status_tag = "online" if ip['malware'].strip().lower() == "online" else "value"
                self.write(f"{ip['malware']}\n", status_tag)
                self.write("  " + "─"*56 + "\n", "divider")
                self.report_content += f"IP: {ip['ip']} Port: {ip['port']} Status: {ip['malware']}\n"

        if self.var_ssl.get():
            self.status_var.set("Fetching SSL Blacklist...")
            self.write("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", "divider")
            self.write(" SSL BLACKLIST — MALICIOUS CERTIFICATES\n", "section")
            self.write("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", "divider")
            certs = get_ssl_blacklist()
            self.report_content += "\nSSL BLACKLIST\n" + "="*60 + "\n"
            for cert in certs:
                self.write(f"\n  Date:        ", "key")
                self.write(f"{cert['date']}\n", "value")
                self.write(f"  SHA1:        ", "key")
                self.write(f"{cert['sha1']}\n", "value")
                self.write(f"  Malware:     ", "key")
                self.write(f"{cert['malware']}\n", "value")
                self.write("  " + "─"*56 + "\n", "divider")
                self.report_content += f"SHA1: {cert['sha1']} Malware: {cert['malware']}\n"

        self.status_var.set(f"Done — fetched at {now}")
        self.run_btn.configure(state="normal", text="RUN THREAT INTEL FETCH")

if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatIntelApp(root)
    root.mainloop()