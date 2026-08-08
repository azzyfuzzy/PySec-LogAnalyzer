import re, sys
from collections import defaultdict
ATTACK_PATTERNS = {'SQL Injection (SQLi)': [r'(?i)UNION\s+SELECT', r'(?i)OR\s+1=1', r'(?i)\'\s*OR\s*\'', r'%27%20OR%20'], 'Cross-Site Scripting (XSS)': [r'(?i)<script.*?>', r'(?i)javascript:', r'(?i)onerror=', r'%3Cscript%3E'], 'Path Traversal': [r'\.\./\.\./', r'/etc/passwd', r'%2e%2e%2f']}
def parse_log_line(line):
    m = re.match(r'^(\S+) \S+ \S+ \[(.*?)\] "(GET|POST|PUT|DELETE) (\S+) HTTP/\d\.\d" (\d{3}) (\d+|-)', line)
    return {'ip': m.group(1), 'timestamp': m.group(2), 'method': m.group(3), 'url': m.group(4), 'status': int(m.group(5))} if m else None
def scan_log(filepath, threshold=5):
    print('='*60 + '\n   PySec-LogAnalyzer | Analyzing: ' + filepath + '\n' + '='*60 + '\n')
    suspicious, failed_logins, total = [], defaultdict(int), 0
    try:
        with open(filepath, 'r') as f:
            for idx, line in enumerate(f, 1):
                total += 1
                entry = parse_log_line(line.strip())
                if not entry: continue
                ip, url, status = entry['ip'], entry['url'], entry['status']
                for atype, patterns in ATTACK_PATTERNS.items():
                    for p in patterns:
                        if re.search(p, url): suspicious.append({'line': idx, 'ip': ip, 'type': atype, 'url': url})
                if 'login' in url.lower() and status in [401, 403]: failed_logins[ip] += 1
        print(f'[✓] Processed {total} log entries.\n')
        if suspicious:
            print(f'[!] THREAT ALERT: {len(suspicious)} Malicious Payload(s) Detected:')
            for a in suspicious: print(f"  • Line {a['line']} | IP: {a['ip']:<15} | Attack: {a['type']}\n    URL: {a['url']}\n")
        print('[!] AUTHENTICATION ANOMALIES:')
        bf = False
        for ip, cnt in failed_logins.items():
            if cnt >= threshold: bf = True; print(f'  • [HIGH RISK] Potential Brute-Force attack from IP: {ip} ({cnt} failed attempts)')
        if not bf: print('  • [✓] No brute-force login attempts detected above threshold.')
    except FileNotFoundError: print(f'[X] Error: File not found at {filepath}')
if __name__ == '__main__': scan_log(sys.argv[1] if len(sys.argv) > 1 else 'logs/sample_access.log')
