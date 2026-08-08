# 🛡️ PySec-LogAnalyzer

An automated Python-based log parser and threat detection engine designed to ingest web server access logs (Nginx/Apache), identify malicious web payload injections (SQLi, XSS, Path Traversal), and alert on HTTP Brute-Force authentication attacks.

## 🚀 Key Features
- **Pattern-Based Threat Detection:** Identifies SQLi, XSS, and Path Traversal.
- **Authentication Anomaly Engine:** Flags Brute-Force attack attempts.
- **Zero-Dependency Core:** Standard Python libraries only.

## 💻 Usage
```bash
git clone https://github.com/AzzyFuzzy/PySec-LogAnalyzer.git
cd PySec-LogAnalyzer
python src/scanner.py logs/sample_access.log
```
