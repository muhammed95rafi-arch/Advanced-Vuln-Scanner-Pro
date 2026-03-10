#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║          VULNERABILITY SCANNER PRO - WITH AUTO REPORT    ║
║          For Educational Use Only                        ║
║          Only test systems you OWN/AUTHORIZED            ║
╚══════════════════════════════════════════════════════════╝
"""

import requests
import json
import sys
import os
import argparse
import datetime
import urllib.parse
import re

requests.packages.urllib3.disable_warnings()

# ─────────────────────────────────────────
# COLOR OUTPUT
# ─────────────────────────────────────────
class C:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def ok(msg):      print(f"  {C.GREEN}[✓]{C.RESET} {msg}")
def fail(msg):    print(f"  {C.RED}[✗]{C.RESET} {C.RED}{msg}{C.RESET}")
def info(msg):    print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def section(msg): print(f"\n{C.CYAN}{C.BOLD}[*] {msg}{C.RESET}")

# ─────────────────────────────────────────
# DATA STORE
# ─────────────────────────────────────────
scan_data = {
    "target": "",
    "timestamp": "",
    "findings": [],
    "summary": {},
    "total_issues": 0
}

def add_finding(category, title, severity, status, description, remediation, evidence=""):
    scan_data["findings"].append({
        "category": category,
        "title": title,
        "severity": severity,   # HIGH / MEDIUM / LOW / INFO
        "status": status,       # PASS / FAIL / WARNING
        "description": description,
        "remediation": remediation,
        "evidence": evidence
    })

# ─────────────────────────────────────────
# CHECKS
# ─────────────────────────────────────────
def check_security_headers(url):
    section("Checking Security Headers...")
    headers_to_check = {
        "X-Frame-Options":           ("MEDIUM", "Prevents clickjacking attacks.",
                                      "Add: X-Frame-Options: DENY"),
        "X-Content-Type-Options":    ("LOW",    "Prevents MIME-type sniffing.",
                                      "Add: X-Content-Type-Options: nosniff"),
        "Strict-Transport-Security": ("HIGH",   "Enforces HTTPS connections.",
                                      "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        "Content-Security-Policy":   ("HIGH",   "Mitigates XSS and data injection.",
                                      "Define a strong Content-Security-Policy for your site."),
        "X-XSS-Protection":          ("LOW",    "Enables browser XSS filter.",
                                      "Add: X-XSS-Protection: 1; mode=block"),
        "Referrer-Policy":           ("LOW",    "Controls referrer info sent with requests.",
                                      "Add: Referrer-Policy: no-referrer-when-downgrade"),
        "Permissions-Policy":        ("LOW",    "Controls browser feature access.",
                                      "Add: Permissions-Policy: geolocation=(), microphone=()"),
    }
    try:
        r = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        count = 0
        for header, (sev, desc, fix) in headers_to_check.items():
            if header in r.headers:
                ok(f"{header} - Present")
                add_finding("Security Headers", header, "INFO", "PASS",
                             f"{header} is present.", "No action needed.")
            else:
                fail(f"{header} - MISSING")
                add_finding("Security Headers", f"Missing {header}", sev, "FAIL",
                             desc, fix)
                count += 1
        scan_data["summary"]["SECURITY_HEADERS"] = count
        return count
    except Exception as e:
        fail(f"Could not check headers: {e}")
        return 0

def check_ssl(url):
    section("Checking SSL/TLS...")
    count = 0
    try:
        try:
            r = requests.get(url, timeout=10, verify=True)
            ok("HTTPS is valid and certificate trusted")
            add_finding("SSL/TLS", "HTTPS Enabled", "INFO", "PASS",
                         "HTTPS is active with trusted certificate.", "No action needed.")
        except requests.exceptions.SSLError:
            fail("SSL Certificate Error / Untrusted")
            add_finding("SSL/TLS", "SSL Certificate Issue", "HIGH", "FAIL",
                         "SSL certificate is invalid or untrusted.",
                         "Renew/install a valid SSL certificate from a trusted CA.")
            count += 1

        http_url = url.replace("https://", "http://")
        try:
            r2 = requests.get(http_url, timeout=10, verify=False, allow_redirects=False)
            if r2.status_code in [301, 302] and "https" in r2.headers.get("Location", ""):
                ok("HTTP properly redirects to HTTPS")
                add_finding("SSL/TLS", "HTTP->HTTPS Redirect", "INFO", "PASS",
                             "HTTP is redirected to HTTPS.", "No action needed.")
            else:
                fail("HTTP does NOT redirect to HTTPS")
                add_finding("SSL/TLS", "Missing HTTP->HTTPS Redirect", "MEDIUM", "FAIL",
                             "HTTP requests are not redirected to HTTPS.",
                             "Configure 301 redirect for all HTTP traffic to HTTPS.")
                count += 1
        except:
            info("Could not check HTTP redirect")

        scan_data["summary"]["SSL"] = count
        return count
    except Exception as e:
        fail(f"SSL check error: {e}")
        return 0

def check_xss(url):
    section("Checking for Reflected XSS...")
    xss_payloads = [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
    ]
    count = 0
    try:
        for payload in xss_payloads:
            test_url = f"{url}?q={urllib.parse.quote(payload)}"
            r = requests.get(test_url, timeout=10, verify=False)
            if payload in r.text:
                fail(f"Possible XSS reflected: {payload[:40]}")
                add_finding("XSS", "Reflected XSS Detected", "HIGH", "FAIL",
                             f"Payload reflected in response: {payload}",
                             "Sanitize all user inputs. Use Content-Security-Policy.",
                             evidence=f"URL: {test_url}")
                count += 1
        if count == 0:
            ok("No obvious XSS found in common parameters")
            add_finding("XSS", "XSS Basic Check", "INFO", "PASS",
                         "No reflected XSS found.", "No action needed.")
        scan_data["summary"]["XSS"] = count
        return count
    except Exception as e:
        fail(f"XSS check error: {e}")
        return 0

def check_sqli(url):
    section("Checking for SQL Injection...")
    sqli_payloads = ["'", '"', "' OR '1'='1"]
    error_patterns = ["sql syntax", "mysql_fetch", "unclosed quotation",
                      "sqlite3", "pg_query", "syntax error", "ora-01756"]
    count = 0
    try:
        for payload in sqli_payloads:
            test_url = f"{url}?id={urllib.parse.quote(payload)}"
            r = requests.get(test_url, timeout=10, verify=False)
            for pattern in error_patterns:
                if pattern.lower() in r.text.lower():
                    fail(f"Possible SQL error with payload: {payload}")
                    add_finding("SQL Injection", "Possible SQL Injection", "HIGH", "FAIL",
                                 f"SQL error pattern '{pattern}' found in response.",
                                 "Use parameterized queries / prepared statements.",
                                 evidence=f"Payload: {payload} | Pattern: {pattern}")
                    count += 1
                    break
        if count == 0:
            ok("No obvious SQL errors detected")
            add_finding("SQL Injection", "SQL Injection Basic Check", "INFO", "PASS",
                         "No SQL error patterns found.", "No action needed.")
        scan_data["summary"]["SQLI"] = count
        return count
    except Exception as e:
        fail(f"SQLi check error: {e}")
        return 0

def check_directories(url):
    section("Checking Common Sensitive Directories...")
    sensitive_paths = [
        "/wp-admin", "/admin", "/login", "/phpmyadmin", "/.git",
        "/config", "/backup", "/robots.txt", "/.env", "/api/v1",
        "/uploads", "/server-status", "/wp-config.php", "/.htaccess"
    ]
    count = 0
    try:
        base = url.rstrip("/")
        for path in sensitive_paths:
            try:
                r = requests.get(base + path, timeout=8, verify=False, allow_redirects=False)
                if r.status_code == 200:
                    fail(f"FOUND ({r.status_code}): {base + path}")
                    sev = "HIGH" if path in ["/.git", "/.env", "/wp-config.php", "/.htaccess"] else "MEDIUM"
                    add_finding("Sensitive Directories", f"Accessible: {path}", sev, "FAIL",
                                 f"Sensitive path publicly accessible: {base + path}",
                                 f"Restrict access to {path} via server config or .htaccess.",
                                 evidence=f"HTTP {r.status_code} at {base + path}")
                    count += 1
                elif r.status_code in [301, 302]:
                    info(f"Redirect ({r.status_code}): {base + path}")
            except:
                pass
        if count == 0:
            ok("No sensitive directories found accessible")
        scan_data["summary"]["DIRECTORIES"] = count
        return count
    except Exception as e:
        fail(f"Directory check error: {e}")
        return 0

def check_idor(url):
    section("Checking for IDOR-prone Parameters...")
    idor_params = ["id", "user_id", "account", "order", "invoice", "file"]
    count = 0
    try:
        for param in idor_params:
            test_url = f"{url}?{param}=1"
            r = requests.get(test_url, timeout=8, verify=False)
            if r.status_code == 200 and len(r.text) > 100:
                info(f"Potential IDOR parameter: ?{param}=")
                add_finding("IDOR", f"Potential IDOR: ?{param}=", "MEDIUM", "WARNING",
                             f"Parameter '{param}' returns data - may be IDOR vulnerable.",
                             "Implement authorization checks. Verify user owns the resource.",
                             evidence=f"URL: {test_url} returned HTTP 200")
                count += 1
        if count == 0:
            ok("No obvious IDOR parameters found")
            add_finding("IDOR", "IDOR Basic Check", "INFO", "PASS",
                         "No obvious IDOR-prone parameters.", "No action needed.")
        scan_data["summary"]["IDOR"] = count
        return count
    except Exception as e:
        fail(f"IDOR check error: {e}")
        return 0

# ─────────────────────────────────────────
# REPORT GENERATORS
# ─────────────────────────────────────────
SEVERITY_COLOR = {
    "HIGH":   ("#e74c3c", "🔴"),
    "MEDIUM": ("#e67e22", "🟠"),
    "LOW":    ("#f1c40f", "🟡"),
    "INFO":   ("#27ae60", "🟢"),
}

def generate_html_report(filename):
    target = scan_data["target"]
    ts = scan_data["timestamp"]
    total = scan_data["total_issues"]

    rows = ""
    for f in scan_data["findings"]:
        sc, si = SEVERITY_COLOR.get(f["severity"], ("#999", "⚪"))
        stc = {"FAIL": "#e74c3c", "PASS": "#27ae60", "WARNING": "#e67e22"}.get(f["status"], "#999")
        ev = f'<br><small><b>Evidence:</b> <code>{f["evidence"]}</code></small>' if f["evidence"] else ""
        rows += f"""
        <tr class="{'fail-row' if f['status']!='PASS' else ''}">
          <td><span class="badge" style="background:{sc}">{si} {f['severity']}</span></td>
          <td><b>{f['title']}</b><br><small style="color:#888">{f['category']}</small>{ev}</td>
          <td><span style="font-weight:bold;color:{stc}">{f['status']}</span></td>
          <td>{f['description']}</td>
          <td style="color:#2ecc71"><b>Fix:</b> {f['remediation']}</td>
        </tr>"""

    summary_cards = ""
    for k, v in scan_data["summary"].items():
        color = "#27ae60" if v == 0 else "#e74c3c"
        summary_cards += f'<div class="card" style="border-left:4px solid {color}"><b>{k}</b><br><span style="font-size:1.4em;color:{color}">{v} issue(s)</span></div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vuln Report - {target}</title>
<style>
  body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}}
  h1{{color:#58a6ff;border-bottom:2px solid #21262d;padding-bottom:10px}}
  h2{{color:#79c0ff;margin-top:30px}}
  .meta{{background:#161b22;padding:15px;border-radius:8px;margin:15px 0}}
  .meta span{{margin-right:20px;color:#8b949e}}
  .meta b{{color:#c9d1d9}}
  .cards{{display:flex;flex-wrap:wrap;gap:15px;margin:20px 0}}
  .card{{background:#161b22;border-radius:8px;padding:15px 20px;min-width:140px}}
  table{{width:100%;border-collapse:collapse;margin-top:20px}}
  th{{background:#21262d;color:#8b949e;padding:10px;text-align:left;font-size:.85em;text-transform:uppercase}}
  td{{padding:10px;border-bottom:1px solid #21262d;vertical-align:top;font-size:.9em}}
  .fail-row{{background:rgba(231,76,60,.06)}}
  .badge{{padding:3px 8px;border-radius:4px;font-size:.8em;color:#fff;white-space:nowrap}}
  code{{background:#21262d;padding:2px 6px;border-radius:4px;font-size:.82em}}
  .total{{font-size:2em;font-weight:bold;color:{'#e74c3c' if total > 0 else '#27ae60'}}}
  .poc{{border:2px dashed #30363d;border-radius:8px;padding:30px;text-align:center;color:#8b949e;margin:10px 0}}
  .footer{{text-align:center;color:#30363d;font-size:.75em;margin-top:40px;padding-top:20px;border-top:1px solid #21262d}}
</style>
</head>
<body>
<h1>🛡️ Vulnerability Scan Report</h1>
<div class="meta">
  <span>🎯 <b>Target:</b> {target}</span>
  <span>🕐 <b>Time:</b> {ts}</span>
  <span>📊 <b>Total Issues:</b> <span class="total">{total}</span></span>
</div>
<h2>📋 Summary</h2>
<div class="cards">{summary_cards}</div>
<h2>🔍 Detailed Findings</h2>
<table>
  <tr><th>Severity</th><th>Finding</th><th>Status</th><th>Description</th><th>Remediation</th></tr>
  {rows}
</table>
<h2>📸 Screenshots / PoC Evidence</h2>
<div class="poc">📷 Attach your proof-of-concept screenshots / recordings here<br>
<small>Add screenshots manually to document visual evidence of findings</small></div>
<div class="footer">⚠️ For Educational &amp; Authorized Testing Use Only | Vuln-Scanner Pro</div>
</body></html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  {C.GREEN}[✓] HTML Report: {filename}{C.RESET}")

def generate_txt_report(filename):
    lines = ["=" * 60, "     VULNERABILITY SCAN REPORT", "=" * 60,
             f"Target  : {scan_data['target']}",
             f"Time    : {scan_data['timestamp']}",
             f"Issues  : {scan_data['total_issues']}", "=" * 60,
             "\nSUMMARY:"]
    for k, v in scan_data["summary"].items():
        lines.append(f"  {k}: {v} issue(s)")
    lines.append("\nFINDINGS (Issues only):")
    lines.append("-" * 60)
    for f in scan_data["findings"]:
        if f["status"] == "PASS":
            continue
        lines += [f"\n[{f['severity']}] {f['title']} ({f['category']})",
                  f"  Status      : {f['status']}",
                  f"  Description : {f['description']}",
                  f"  Fix         : {f['remediation']}"]
        if f["evidence"]:
            lines.append(f"  Evidence    : {f['evidence']}")
    lines += ["\n" + "=" * 60, "For authorized testing use only."]
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"  {C.GREEN}[✓] TXT Report: {filename}{C.RESET}")

def generate_json_report(filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, indent=2, ensure_ascii=False)
    print(f"  {C.GREEN}[✓] JSON Report: {filename}{C.RESET}")

def generate_pdf_report(filename):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.units import mm

        doc = SimpleDocTemplate(filename, pagesize=A4,
                                leftMargin=20*mm, rightMargin=20*mm,
                                topMargin=20*mm, bottomMargin=20*mm)
        styles = getSampleStyleSheet()
        story = []
        normal = styles["Normal"]
        h2 = ParagraphStyle("H2", parent=styles["Heading2"],
                             textColor=colors.HexColor("#2980b9"))
        title_s = ParagraphStyle("T", parent=styles["Title"],
                                  textColor=colors.HexColor("#2c3e50"), fontSize=18)

        story.append(Paragraph("Vulnerability Scan Report", title_s))
        story.append(Spacer(1, 5*mm))
        story.append(Paragraph(f"<b>Target:</b> {scan_data['target']}", normal))
        story.append(Paragraph(f"<b>Time:</b> {scan_data['timestamp']}", normal))
        story.append(Paragraph(f"<b>Total Issues:</b> {scan_data['total_issues']}", normal))
        story.append(Spacer(1, 6*mm))
        story.append(Paragraph("Summary", h2))
        for k, v in scan_data["summary"].items():
            c = "red" if v > 0 else "green"
            story.append(Paragraph(f"• <b>{k}</b>: <font color='{c}'>{v} issue(s)</font>", normal))
        story.append(Spacer(1, 6*mm))
        story.append(Paragraph("Findings", h2))

        sev_colors = {
            "HIGH":   colors.HexColor("#e74c3c"),
            "MEDIUM": colors.HexColor("#e67e22"),
            "LOW":    colors.HexColor("#f39c12"),
            "INFO":   colors.HexColor("#27ae60"),
        }
        for f in scan_data["findings"]:
            if f["status"] == "PASS":
                continue
            c = sev_colors.get(f["severity"], colors.grey)
            rows = [
                [Paragraph(f"<b>[{f['severity']}] {f['title']}</b>", normal), ""],
                ["Category", f["category"]],
                ["Status", f["status"]],
                ["Description", f["description"]],
                ["Remediation", f["remediation"]],
            ]
            if f["evidence"]:
                rows.append(["Evidence", f["evidence"]])
            t = Table(rows, colWidths=[38*mm, 132*mm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), c),
                ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                ("SPAN",       (0, 0), (1, 0)),
                ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#f0f0f0")),
                ("FONTSIZE",   (0, 0), (-1, -1), 8),
                ("GRID",       (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("VALIGN",     (0, 0), (-1, -1), "TOP"),
                ("PADDING",    (0, 0), (-1, -1), 5),
            ]))
            story.append(t)
            story.append(Spacer(1, 4*mm))

        story.append(Spacer(1, 6*mm))
        story.append(Paragraph("Screenshots / PoC Evidence", h2))
        story.append(Paragraph("[ Attach your proof-of-concept screenshots here ]", normal))
        story.append(Spacer(1, 5*mm))
        story.append(Paragraph("<i>For authorized/educational testing use only.</i>", normal))
        doc.build(story)
        print(f"  {C.GREEN}[✓] PDF Report: {filename}{C.RESET}")
    except ImportError:
        print(f"  {C.YELLOW}[!] reportlab not installed -> pip install reportlab{C.RESET}")
        print(f"  {C.YELLOW}[!] PDF skipped. Other reports still generated.{C.RESET}")

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════╗
║       VULNERABILITY SCANNER PRO - AUTO REPORT            ║
║       HTML | PDF | TXT | JSON                            ║
╠══════════════════════════════════════════════════════════╣
║  ⚠️  For Authorized/Educational Use Only                 ║
║  Only test systems you OWN or have PERMISSION            ║
╚══════════════════════════════════════════════════════════╝{C.RESET}
""")

def main():
    banner()
    parser = argparse.ArgumentParser(description="Vulnerability Scanner Pro with Auto Report")
    parser.add_argument("url", help="Target URL e.g. https://example.com")
    parser.add_argument("--checks", nargs="+",
                        choices=["headers", "ssl", "xss", "sqli", "dirs", "idor"],
                        default=["headers", "ssl", "xss", "sqli", "dirs", "idor"])
    parser.add_argument("--report", nargs="+",
                        choices=["html", "pdf", "txt", "json"],
                        default=["html", "pdf", "txt", "json"])
    parser.add_argument("--output", default="reports",
                        help="Output folder for reports (default: reports/)")
    args = parser.parse_args()

    url = args.url
    if not url.startswith("http"):
        url = "https://" + url

    ts = datetime.datetime.now()
    scan_data["target"] = url
    scan_data["timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S")

    print(f"  {C.CYAN}Target : {url}{C.RESET}")
    print(f"  {C.CYAN}Time   : {scan_data['timestamp']}{C.RESET}")

    total = 0
    if "headers" in args.checks: total += check_security_headers(url)
    if "ssl"     in args.checks: total += check_ssl(url)
    if "xss"     in args.checks: total += check_xss(url)
    if "sqli"    in args.checks: total += check_sqli(url)
    if "dirs"    in args.checks: total += check_directories(url)
    if "idor"    in args.checks: total += check_idor(url)

    scan_data["total_issues"] = total

    print(f"\n{C.BOLD}{'─'*50}")
    print("  SCAN COMPLETE - SUMMARY")
    print(f"{'─'*50}{C.RESET}")
    for k, v in scan_data["summary"].items():
        c = C.GREEN if v == 0 else C.RED
        print(f"  {c}[{'✓' if v==0 else '✗'}] {k}: {v} issue(s){C.RESET}")
    c = C.GREEN if total == 0 else C.RED
    print(f"\n  {c}Total Issues Found: {total}{C.RESET}")
    print(f"{'─'*50}")

    # Generate all reports
    os.makedirs(args.output, exist_ok=True)
    safe = re.sub(r'[^\w]', '_', url.replace("https://","").replace("http://",""))[:35]
    stamp = ts.strftime("%Y%m%d_%H%M%S")
    base = os.path.join(args.output, f"vuln_report_{safe}_{stamp}")

    print(f"\n{C.CYAN}{C.BOLD}[*] Generating Reports...{C.RESET}")
    if "html" in args.report: generate_html_report(base + ".html")
    if "pdf"  in args.report: generate_pdf_report(base + ".pdf")
    if "txt"  in args.report: generate_txt_report(base + ".txt")
    if "json" in args.report: generate_json_report(base + ".json")

    print(f"\n  {C.GREEN}✅ Reports saved in: {os.path.abspath(args.output)}/{C.RESET}\n")

if __name__ == "__main__":
    main()