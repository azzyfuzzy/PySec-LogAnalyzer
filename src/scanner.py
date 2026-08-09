import argparse
from datetime import datetime
import json
import os
import re
from collections import defaultdict

# Predefined attack signatures
ATTACK_PATTERNS = {
    "SQL Injection": [r"UNION\s+SELECT", r"OR\s+1=1", r"SELECT\s+\*"],
    "XSS (Cross-Site Scripting)": [r"<script>", r"javascript:", r"onerror="],
    "Path Traversal": [r"\.\./\.\.", r"/etc/passwd", r"boot\.ini"]
}


def parse_log_line(line):
    """
    Parses a standard Apache/Nginx access log entry using regex.
    """
    pattern = r'(\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(.*?)\]\s+"(\w+)\s+(.*?)\s+HTTP/.*?"\s+(\d+)\s+(\d+|-)'
    match = re.search(pattern, line)
    if match:
        return {
            "ip": match.group(1),
            "timestamp": match.group(2),
            "method": match.group(3),
            "url": match.group(4),
            "status": int(match.group(5)),
            "bytes": match.group(6)
        }
    return None


def generate_markdown_report(total_lines, suspicious_activities, failed_logins, threshold, report_path="reports/threat_report.md"):
    """
    Generates a structured Markdown security report.
    """
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# PySec-LogAnalyzer Threat Report\n\n")
        f.write(f"**Generated:** {timestamp}  \n")
        f.write(f"**Total Log Entries Processed:** {total_lines}\n\n")
        f.write("---\n\n")

        # Section 1: Detected Attack Payloads
        f.write("## Detected Malicious Payloads\n\n")
        if suspicious_activities:
            f.write("| IP Address | Category | Detected Payload/URL |\n")
            f.write("| :--- | :--- | :--- |\n")
            for item in suspicious_activities:
                f.write(f"| `{item['ip']}` | **{item['category']}** | `{item['url']}` |\n")
        else:
            f.write("No signature-based attack payloads detected.\n")

        f.write("\n---\n\n")

        # Section 2: Brute-Force Anomalies
        f.write("## Brute-Force Authentication Anomalies\n\n")
        flagged_ips = {ip: count for ip, count in failed_logins.items() if count >= threshold}
        
        if flagged_ips:
            f.write(f"*(Flagged IPs with failed logins ≥ {threshold})*\n\n")
            f.write("| IP Address | Failed Attempts | Risk Level |\n")
            f.write("| :--- | :--- | :--- |\n")
            for ip, count in flagged_ips.items():
                risk = "HIGH" if count >= (threshold * 2) else "MEDIUM"
                f.write(f"| `{ip}` | {count} | **{risk}** |\n")
        else:
            f.write(f"No IP addresses exceeded the failed login threshold ({threshold}).\n")

    print(f"[+] Markdown report successfully written to: {report_path}")


def generate_json_report(total_lines, suspicious_activities, failed_logins, threshold, json_path="reports/threat_report.json"):
    """
    Exports findings into structured JSON for tool integration and dashboards.
    """
    os.makedirs(os.path.dirname(json_path), exist_ok=True)
    flagged_ips = {ip: count for ip, count in failed_logins.items() if count >= threshold}

    data = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "total_processed_lines": total_lines,
            "threshold": threshold
        },
        "summary": {
            "total_payload_alerts": len(suspicious_activities),
            "total_brute_force_ips": len(flagged_ips)
        },
        "detected_payloads": suspicious_activities,
        "flagged_brute_force_ips": [
            {
                "ip": ip,
                "failed_attempts": count,
                "risk_level": "HIGH" if count >= (threshold * 2) else "MEDIUM"
            }
            for ip, count in flagged_ips.items()
        ]
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    print(f"[+] JSON report successfully written to: {json_path}")


def scan_log(log_filepath, threshold, json_output_path=None):
    """
    Scans the access log file line by line.
    """
    if not os.path.exists(log_filepath):
        print(f"[-] Error: Target log file '{log_filepath}' not found.")
        return

    print(f"[*] PySec-LogAnalyzer | Scanning: {log_filepath}")
    
    total_lines = 0
    suspicious_activities = []
    failed_logins = defaultdict(int)

    with open(log_filepath, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            total_lines += 1
            parsed = parse_log_line(line)
            if not parsed:
                continue

            # Check 1: Attack Payload Signature Matching
            for category, patterns in ATTACK_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, parsed["url"], re.IGNORECASE):
                        suspicious_activities.append({
                            "ip": parsed["ip"],
                            "category": category,
                            "url": parsed["url"]
                        })
                        break

            # Check 2: Behavioral Brute-Force (Failed Login Tracking)
            if parsed["status"] in (401, 403):
                failed_logins[parsed["ip"]] += 1

    # Print Terminal Summary
    print(f"[+] Processed {total_lines} lines.")
    print(f"[+] Detected {len(suspicious_activities)} payload alerts.")
    
    # Export Reports
    generate_markdown_report(total_lines, suspicious_activities, failed_logins, threshold)
    
    if json_output_path:
        generate_json_report(total_lines, suspicious_activities, failed_logins, threshold, json_output_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PySec-LogAnalyzer: Analyze web server access logs for malicious payloads and brute-force attacks."
    )
    parser.add_argument(
        "-l", "--log", 
        default="logs/sample_access.log", 
        help="Path to the access log file (default: logs/sample_access.log)"
    )
    parser.add_argument(
        "-t", "--threshold", 
        type=int, 
        default=5, 
        help="Failed login threshold for brute-force detection (default: 5)"
    )
    parser.add_argument(
        "-j", "--json",
        nargs="?",
        const="reports/threat_report.json",
        default=None,
        help="Export findings to JSON format (optional path, default: reports/threat_report.json)"
    )

    args = parser.parse_args()
    scan_log(args.log, args.threshold, args.json)
