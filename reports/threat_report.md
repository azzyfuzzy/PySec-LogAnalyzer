# PySec-LogAnalyzer Threat Report

- **Analyzed Log File:** `logs/sample_access.log`
- **Total Lines Processed:** 12
- **Malicious Payloads Detected:** 4

--- 

## Detected Payload Attacks

| Line | Source IP | Attack Type | Targeted URL |
| :--- | :--- | :--- | :--- |
| 10 | `172.16.0.99` | **SQL Injection (SQLi)** | `/products.php?id=1%27%20OR%201=1--` |
| 11 | `172.16.0.99` | **Cross-Site Scripting (XSS)** | `/search.php?q=<script>alert(%27XSS%27)</script>` |
| 12 | `192.168.1.50` | **Path Traversal** | `/../../../../etc/passwd` |
| 12 | `192.168.1.50` | **Path Traversal** | `/../../../../etc/passwd` |

---

## Authentication Anomalies (Brute-Force)

- **[HIGH RISK]** Potential Brute-Force attack from IP `10.0.0.45` (6 failed login attempts)
