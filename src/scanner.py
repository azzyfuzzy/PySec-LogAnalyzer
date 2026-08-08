import re
import sys
import os
from collections import defaultdict

ATTACK_PATTERNS = {
    "SQL Injection (SQLi)": [r"(?i)UNION\s+SELECT", r"(?i)OR\s+1=1", r"(?i)'\s*OR\s*'", r"%27%20OR%20"],
    "Cross-Site Scripting (XSS)": [r"(?i)<script.*?>", r"(?i)javascript:", r"(?i)onerror=", r"%3Cscript%3E"],
    "Path Traversal": [r"\.\./\.\./", r"/etc/passwd", r"%2e%2e%2f"]
}

def parse_log_line(line):
    log_pattern = r'^(\S+) \S+ \S+ \[(.*?)\] "(GET|POST|PUT|DELETE) (\S+) HTTP/\d\.\d" (\d{3}) (\d+|-)'
    match = re.match(log_pattern, line)
    if match:
        return {
            "ip": match.group(1),
            "timestamp": match.group(2),
            "method": match.group(3),
            "url": match.group(4),
            "status": int(match.group(5))
        }
    return None

def generate_markdown_report(log_filepath, total_lines, suspicious_activities, failed_logins, threshold, report_path="reports/threat_report.md"):
    """Writes the threat detection findings to a structured Markdown report file."""
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
    with open(report_path, "w", encoding="utf-8") as report:
        report.write("# PySec-LogAnalyzer Threat Report\n\n")
        report.write(f"- **Analyzed Log File:** `{log_filepath}`\n")
        report.write(f"- **Total Lines Processed:** {total_lines}\n")
        report.write(f"- **Malicious Payloads Detected:** {len(suspicious_activities)}\n\n")
        report.write("--- \n\n")
        
        report.write("## Detected Payload Attacks\n\n")
        if suspicious_activities:
            report.write("| Line | Source IP | Attack Type | Targeted URL |\n")
            report.write("| :--- | :--- | :--- | :--- |\n")
            for alert in suspicious_activities:
                report.write(f"| {alert['line']} | `{alert['ip']}` | **{alert['type']}** | `{alert['url']}` |\n")
        else:
            report.write("*No explicit payload attacks detected.*\n")
            
        report.write("\n---\n\n")
        report.write("## Authentication Anomalies (Brute-Force)\n\n")
        brute_force_found = False
        for ip, count in failed_logins.items():
            if count >= threshold:
                brute_force_found = True
                report.write(f"- **[HIGH RISK]** Potential Brute-Force attack from IP `{ip}` ({count} failed login attempts)\n")
        
        if not brute_force_found:
            report.write("*No brute-force login attempts detected above threshold.*\n")

    print(f"[+] Threat report generated successfully at: {report_path}")

def scan_log(log_filepath, brute_force_threshold=5):
    print("=" * 60)
    print(f"   PySec-LogAnalyzer | Analyzing: {log_filepath}")
    print("=" * 60 + "\n")
    
    suspicious_activities = []
    failed_logins_per_ip = defaultdict(int)
    total_lines = 0

    try:
        with open(log_filepath, 'r', encoding='utf-8', errors='ignore') as file:
            for line_num, line in enumerate(file, 1):
                total_lines += 1
                entry = parse_log_line(line.strip())
                if not entry:
                    continue

                ip, url, status = entry["ip"], entry["url"], entry["status"]

                for attack_type, patterns in ATTACK_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, url):
                            suspicious_activities.append({
                                "line": line_num, "ip": ip, "type": attack_type, "url": url
                            })

                if "login" in url.lower() and status in [401, 403]:
                    failed_logins_per_ip[ip] += 1

        print(f"[+] Processed {total_lines} log entries.\n")

        if suspicious_activities:
            print(f"[!] THREAT ALERT: {len(suspicious_activities)} Malicious Payload(s) Detected:")
            for alert in suspicious_activities:
                print(f"  * Line {alert['line']} | IP: {alert['ip']:<15} | Attack: {alert['type']}")
                print(f"    URL: {alert['url']}\n")
        else:
            print("[+] No explicit payload attacks detected.\n")

        print("[!] AUTHENTICATION ANOMALIES:")
        brute_force_found = False
        for ip, count in failed_logins_per_ip.items():
            if count >= brute_force_threshold:
                brute_force_found = True
                print(f"  * [HIGH RISK] Potential Brute-Force attack from IP: {ip} ({count} failed attempts)")

        if not brute_force_found:
            print("  * [+] No brute-force login attempts detected above threshold.")
            
        print("\n" + "-" * 60)
        generate_markdown_report(log_filepath, total_lines, suspicious_activities, failed_logins_per_ip, brute_force_threshold)

    except FileNotFoundError:
        print(f"[X] Error: Could not find log file at '{log_filepath}'")

if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "logs/sample_access.log"
    scan_log(filepath)
