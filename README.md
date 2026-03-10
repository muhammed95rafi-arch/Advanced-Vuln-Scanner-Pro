# 🛡️ Vuln-Scanner Pro

<div align="center">

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Termux%20|%20Kali%20|%20Ubuntu%20|%20iSH-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Educational](https://img.shields.io/badge/Use-Educational%20Only-red?style=for-the-badge)

**A powerful, lightweight vulnerability scanner with automatic report generation.**  
Supports HTML, PDF, TXT, and JSON reports. Runs on Termux, Kali Linux, Ubuntu, and iSH.

</div>

---

## ⚠️ Disclaimer

> This tool is intended **for educational purposes and authorized security testing only**.  
> **Only scan websites/systems you OWN or have explicit written permission to test.**  
> The author is not responsible for any misuse or illegal activity.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 Security Headers Check | Detects missing HTTP security headers |
| 🔒 SSL/TLS Analysis | Validates HTTPS, certificate trust, redirect |
| 💉 XSS Detection | Tests for reflected Cross-Site Scripting |
| 🗃️ SQL Injection Check | Detects common SQL error patterns |
| 📁 Sensitive Directory Scan | Finds exposed admin panels, configs, backups |
| 🔑 IDOR Parameter Detection | Identifies insecure direct object reference params |
| 📊 Auto Report Generation | HTML, PDF, TXT, JSON — generated automatically |
| 🎯 Severity Ratings | HIGH / MEDIUM / LOW / INFO for each finding |
| 🛠️ Remediation Steps | Fix recommendations for every vulnerability |
| 📸 PoC Placeholder | Screenshot section in every report |

---

## 📸 Screenshots

```
╔══════════════════════════════════════════════════════════╗
║       VULNERABILITY SCANNER PRO - AUTO REPORT            ║
║       HTML | PDF | TXT | JSON                            ║
╠══════════════════════════════════════════════════════════╣
║  ⚠️  For Authorized/Educational Use Only                 ║
╚══════════════════════════════════════════════════════════╝

[*] Checking Security Headers...
  [✓] X-Frame-Options - Present
  [✓] Strict-Transport-Security - Present
  [✗] Referrer-Policy - MISSING
  [✗] Permissions-Policy - MISSING

[*] Checking SSL/TLS...
  [✓] HTTPS is valid and certificate trusted
  [✓] HTTP properly redirects to HTTPS

[*] Checking for Reflected XSS...
  [✓] No obvious XSS found

[*] Checking for SQL Injection...
  [✓] No obvious SQL errors detected

[*] Checking Common Sensitive Directories...
  [✗] FOUND (200): https://example.com/robots.txt

──────────────────────────────────────────────────
  SCAN COMPLETE - SUMMARY
──────────────────────────────────────────────────
  [✓] SSL: 0 issue(s)
  [✗] DIRECTORIES: 1 issue(s)

  Total Issues Found: 1

[*] Generating Reports...
  [✓] HTML Report: reports/vuln_report_example_com_20260310.html
  [✓] PDF Report:  reports/vuln_report_example_com_20260310.pdf
  [✓] TXT Report:  reports/vuln_report_example_com_20260310.txt
  [✓] JSON Report: reports/vuln_report_example_com_20260310.json
```

---

## 📦 Installation

### 🤖 Termux (Android)
```bash
pkg update && pkg upgrade -y
pkg install python git -y
pip install requests reportlab
git clone https://github.com/yourusername/Vuln-Scanner-Pro.git
cd Vuln-Scanner-Pro
chmod +x vuln_scanner_pro.py
```

### 🐧 Kali Linux
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip git -y
pip3 install requests reportlab
git clone https://github.com/yourusername/Vuln-Scanner-Pro.git
cd Vuln-Scanner-Pro
chmod +x vuln_scanner_pro.py
```

### 🟠 Ubuntu
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip git -y
pip3 install requests reportlab --break-system-packages
git clone https://github.com/yourusername/Vuln-Scanner-Pro.git
cd Vuln-Scanner-Pro
chmod +x vuln_scanner_pro.py
```

### 📱 iSH (iPhone / iPad)
```bash
apk update && apk upgrade
apk add python3 py3-pip git
pip3 install requests reportlab
git clone https://github.com/yourusername/Vuln-Scanner-Pro.git
cd Vuln-Scanner-Pro
python3 vuln_scanner_pro.py https://yoursite.com
```

---

## 🚀 Usage

### Basic Scan (All checks + All reports)
```bash
python3 vuln_scanner_pro.py https://example.com
```

### Specific Checks Only
```bash
python3 vuln_scanner_pro.py https://example.com --checks headers ssl xss
```

### Specific Report Formats
```bash
python3 vuln_scanner_pro.py https://example.com --report html pdf
```

### Custom Output Folder
```bash
python3 vuln_scanner_pro.py https://example.com --output /sdcard/my_reports
```

### All Options Together
```bash
python3 vuln_scanner_pro.py https://example.com \
  --checks headers ssl xss sqli dirs idor \
  --report html pdf txt json \
  --output ~/reports
```

---

## 📋 Available Checks

| Flag | Check | Description |
|------|-------|-------------|
| `headers` | Security Headers | X-Frame-Options, CSP, HSTS, etc. |
| `ssl` | SSL/TLS | Certificate validity, HTTPS redirect |
| `xss` | Reflected XSS | Common XSS payload injection |
| `sqli` | SQL Injection | Error-based SQL detection |
| `dirs` | Sensitive Dirs | Admin panels, .env, .git, backups |
| `idor` | IDOR Params | Insecure direct object references |

---

## 📊 Report Formats

| Format | Best For |
|--------|----------|
| 🌐 **HTML** | Visual review in browser, sharing with clients |
| 📄 **PDF** | Professional reports, printing |
| 📝 **TXT** | Quick read, terminal friendly |
| 🔧 **JSON** | Integration with other tools / APIs |

Reports include:
- ✅ Vulnerability details with severity rating
- 🛠️ Remediation / fix steps
- 🔍 Evidence (URLs, payloads)
- 📸 PoC screenshot placeholder section

---

## 🗂️ Project Structure

```
Vuln-Scanner-Pro/
├── vuln_scanner_pro.py   # Main scanner script
├── README.md             # This file
├── LICENSE               # MIT License
└── reports/              # Auto-created output folder
    ├── vuln_report_*.html
    ├── vuln_report_*.pdf
    ├── vuln_report_*.txt
    └── vuln_report_*.json
```

---

## 🔧 Requirements

```
Python 3.x
requests
reportlab      (for PDF generation)
```

Install all:
```bash
pip install requests reportlab
```

---

## 🤝 Contributing

Pull requests are welcome!  
For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/NewCheck`)
3. Commit your changes (`git commit -m 'Add new vulnerability check'`)
4. Push to the branch (`git push origin feature/NewCheck`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

Made with ❤️ for the cybersecurity learning community.

> ⚠️ **Legal Notice:** This tool is for **authorized testing and educational use only.**  
> Unauthorized scanning of systems is **illegal** and **unethical**.  
> Always get written permission before testing any system you don't own.

---

<div align="center">
⭐ Star this repo if you found it useful!
</div>
