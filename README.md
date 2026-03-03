# 🔍 Log Analyzer & Threat Detector

A Python-based security tool that parses Apache and Windows authentication logs, detects malicious activity, and generates threat reports mapped to the **MITRE ATT&CK** framework.

Built as part of a cybersecurity portfolio to demonstrate SOC/Blue Team skills in log analysis, threat detection, and incident response.

---

## 🚨 Threat Detection Capabilities

| Threat Type | Severity | MITRE ATT&CK |
|---|---|---|
| Brute Force Login Attempts | HIGH | T1110 - Brute Force |
| Account Lockouts | HIGH | T1110.001 - Password Guessing |
| Suspicious Scanning Tools (SQLMap, Nikto, etc.) | MEDIUM | T1595 - Active Scanning |
| Directory/Path Enumeration | MEDIUM | T1046 - Network Service Discovery |
| HTTP Error Spikes | LOW | T1595.002 - Vulnerability Scanning |
| Known Malicious IP Traffic | CRITICAL | T1071 - Application Layer Protocol |

---

## 📋 Features

- ✅ Auto-detects log format (Apache or Windows)
- ✅ Detects 6 threat categories with severity levels
- ✅ Maps all alerts to MITRE ATT&CK techniques
- ✅ Generates color-coded terminal reports
- ✅ Exports JSON reports for SIEM ingestion
- ✅ Shows top IPs, status codes, and path statistics
- ✅ Works with real-world log formats

---

## 🛠️ Tech Stack

- **Language:** Python 3.x
- **Libraries:** `re`, `json`, `argparse`, `collections`, `pathlib` (all standard library — no installs needed)
- **Log Formats:** Apache Combined Log Format, Windows Security Event Logs

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/sankethsubhas/log-analyzer-threat-detector.git
cd log-analyzer-threat-detector
```

### 2. Run against sample logs
```bash
# Analyze Apache access log
python log_analyzer.py sample_logs/apache_access.log

# Analyze Windows auth log
python log_analyzer.py sample_logs/windows_auth.log

# Auto-detect format
python log_analyzer.py your_log_file.log
```

### 3. Export a JSON report
```bash
python log_analyzer.py sample_logs/apache_access.log --output report.json
```

---

## 📊 Sample Output

```
=================================================================
        LOG ANALYZER & THREAT DETECTOR — REPORT
=================================================================
  File     : apache_access.log
  Generated: 2025-01-15 09:00:00
  Entries  : 40 | Unique IPs: 8
=================================================================

  🚨 THREATS DETECTED: 9

  [HIGH] Brute Force Attack
         IP     : 10.0.0.5
         Detail : 7 failed login attempts detected from 10.0.0.5
         MITRE  : T1110 - Brute Force

  [MEDIUM] Suspicious User Agent
         IP     : 172.16.0.99
         Detail : Scanning tools detected from 172.16.0.99: sqlmap
         MITRE  : T1595 - Active Scanning
...
```

---

## 📁 Project Structure

```
log-analyzer-threat-detector/
│
├── log_analyzer.py          # Main detection engine
├── sample_logs/
│   ├── apache_access.log    # Sample Apache log with attack patterns
│   └── windows_auth.log     # Sample Windows auth log with attack patterns
└── README.md
```

---

## ⚙️ Configuration

You can tune detection thresholds at the top of `log_analyzer.py`:

```python
BRUTE_FORCE_THRESHOLD = 5       # Failed logins to trigger alert
PORT_SCAN_THRESHOLD = 10        # Unique paths to flag enumeration
```

You can also add your own threat intel by updating:
```python
KNOWN_MALICIOUS_IPS = {
    "1.2.3.4",   # Add known bad IPs here
}
```

---

## 🔗 Real-World Relevance

This project simulates core SOC analyst tasks:

- **Log ingestion & parsing** — similar to feeding data into Splunk or Elastic SIEM
- **Threat detection rules** — mirrors SIEM correlation rules and use cases
- **MITRE ATT&CK mapping** — standard practice in modern threat detection
- **Incident reporting** — JSON output can be ingested by downstream tools

---

## 👤 Author

**Sanketh Subhas** — Cybersecurity Analyst  
🔗 [LinkedIn](https://linkedin.com/in/sanketh-subhas) | 🌐 [Portfolio](https://sankethsubhas.netlify.app)

---

## 📄 License

MIT License — feel free to use, modify, and build on this project.
