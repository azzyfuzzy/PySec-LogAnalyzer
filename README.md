#  PySec-LogAnalyzer

A beginner-friendly Python script built to learn the basics of log parsing, web attack detection, threat identification, and automated security reporting. 

I built this project to transition from basic Python scripts to a more practical security tool and to get hands-on experience applying cybersecurity concepts (like SQL Injection, XSS, and Brute Force attacks) using real-world web server log formats.

---

##  Purpose & Learning Goals


Through this project, I practiced:
- **Python Programming Skills:** Practiced writing modular Python scripts, using regular expressions (`re`), manipulating custom data structures (`defaultdict`) and handling CLI arguments (`sys.argv`).
- **Log Parsing:** Using Regular Expressions (`re`) to extract IP addresses, HTTP methods, status codes, and request URLs from Apache/Nginx access logs.
- **Payload Detection:** Matching URL query strings against common attack signatures (SQL Injection, Cross-Site Scripting, and Path Traversal).
- **Behavioral Analysis:** Tracking failed authentication attempts (`401`/`403` status codes) per IP address to detect potential brute-force logins.
- **Automated Reporting:** Writing structured Markdown reports (`reports/threat_report.md`) for SOC/SIEM documentation.

---

##  How It Works

1. **Log Ingestion:** Reads access log entries matching the standard Combined Log Format.
2. **Signature Matching:** Scans requested URLs using regular expressions for malicious patterns like `UNION SELECT`, `<script>`, or `/etc/passwd`.
3. **Threshold Alerting:** Counts failed login requests for each unique IP address and flags IPs that exceed a threshold (default: 5 failed attempts).
4. **Report Exporter:** Automatically exports threat metrics, flagged IPs, and attack URLs to `reports/threat_report.md`.

---

##  How to Run

### Requirements
This project was built to be completely lightweight and plug-and-play. 

* **Python 3.6 or higher** is required.
* **No external dependencies!** It runs purely on Python's Standard Library (`os`, `re`, `json`, `datetime`). You do not need to run `pip install` or set up a virtual environment to use this tool.

### Usage
Clone the repository and run the analyzer against the provided sample log file:

```bash
git clone https://github.com/AzzyFuzzy/PySec-LogAnalyzer.git
cd PySec-LogAnalyzer
python src/scanner.py logs/sample_access.log
```
##  Generated Report Output
When executed, the script generates a structured summary inside reports/threat_report.md:

<img width="953" height="273" alt="image" src="https://github.com/user-attachments/assets/fc760ecd-ace9-41a7-972f-6ad64d72d44f" />
<img width="953" height="365" alt="image" src="https://github.com/user-attachments/assets/48542197-52db-4dfd-8c41-ea26e10123b8" />



