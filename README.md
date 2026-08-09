# PySec-LogAnalyzer

A lightweight Python script I built to get hands-on with log parsing, web attack detection, and automated security reporting.

I built this project to transition from basic Python exercises to a more practical security tool and to get hands-on experience applying cybersecurity concepts (like SQLi, XSS, and Brute Force attacks) and seeing how they actually look inside real web server access logs.

---

### Purpose & What I Learned

Through this project, I practiced key security and coding concepts:
* **Python Fundamentals:** Wrote modular code, handled flexible command-line arguments using `argparse`, and managed dynamic counts using `defaultdict`.
* **Log Parsing:** Used Regular Expressions (`re`) to extract IP addresses, HTTP methods, status codes, and request URLs from Apache/Nginx access logs.
* **Payload Signature Detection:** Evaluated URL query strings against common attack signatures (SQL Injection, Cross-Site Scripting, and Path Traversal).
* **Behavioral Detection:** Tracked failed authentication responses (`401`/`403`) by IP address to spot potential brute-force attempts.
* **Automated Reporting:** Formatted and exported clean Markdown reports (`reports/threat_report.md`) to simulate basic SOC/SIEM documentation.

---

### How It Works

- **Log Ingestion:** Reads web server access logs line-by-line using regular expressions to extract structured fields (IPs, timestamps, methods, URLs, status codes).
- **Signature Matching:** Evaluates request URLs against regular expression patterns to detect embedded malicious payloads (SQL Injection, XSS, and Path Traversal).
- **Threshold Alerting:** Tracks HTTP `401`/`403` failed login responses per unique IP address and flags IPs exceeding the brute-force threshold (default: 5 attempts).
- **Report Exporter:** Automatically generates a structured Markdown document (`reports/threat_report.md`) detailing all detected payload attacks and high-risk IP anomalies.

---

### How to Run

#### Requirements
This project was built to be completely lightweight and plug-and-play.
* Python 3.6 or higher is required.
* **No external dependencies!** It runs purely on Python's Standard Library (`os`, `re`, `argparse`, `sys`). You do not need to run `pip install` or set up a virtual environment to use this tool.

#### Usage

Clone the repository and run the analyzer against the provided sample log file:

```bash
git clone https://github.com/AzzyFuzzy/PySec-LogAnalyzer.git
cd PySec-LogAnalyzer
```
1. Run with default settings (scans logs/sample_access.log with default threshold of 5):
```bash
python src/scanner.py
```
2. Display built-in CLI help menu:
```bash
python src/scanner.py --help
```
3. Run with custom arguments (specify log file or custom brute-force threshold):
```bash
python src/scanner.py -l logs/sample_access.log -t 3
```
| Flag | Long Option | Description | Default Value |
| :--- | :--- | :--- | :--- |
| `-l` | `--log` | Path to the target access log file | `logs/sample_access.log` |
| `-t` | `--threshold` | Failed login threshold for brute-force detection | `5` |
| `-h` | `--help` | Show help message and exit | — |

---

### Generated Report Output
When executed, the script generates a structured summary inside reports/threat_report.md:

<img width="953" height="273" alt="image" src="https://github.com/user-attachments/assets/fc760ecd-ace9-41a7-972f-6ad64d72d44f" />
<img width="953" height="365" alt="image" src="https://github.com/user-attachments/assets/48542197-52db-4dfd-8c41-ea26e10123b8" />



