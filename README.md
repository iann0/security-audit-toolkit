# Security Audit Toolkit
A lightweight Python security auditing tool for checking common security issues on web hosts.

Features
- Hostname and IP resolution
- TCP port scanning
- Basic service identification
- HTTP security header checks
- TLS/HTTPS analysis
- TLS version and cipher detection
- SSL/TLS certificate inspection
- Certificate expiry checking
- Severity-based risk assessment
- JSON report generation
- HTML report generation
- Remediation recommendations

# Project Structure
security-audit-toolkit/
├── auditor.py
├── modules/
│   ├── ports.py
│   ├── headers.py
│   ├── ssl_check.py
│   ├── risk.py
│   ├── report.py
│   └── html_report.py
├── reports/
├── README.md
└── requirements.txt

# Requirements
- Python 3
- A terminal
- Network access for remote targets

The project currently uses Python's standard library, so there are no major third-party dependencies required.

# Installation
Clone the repository:
git clone https://github.com/iann0/security-audit-toolkit.git
Enter the project:

cd security-audit-toolkit

Run a syntax check:

python -m py_compile auditor.py

You can also check the individual modules:

python -m py_compile modules/html_report.py
python -m py_compile modules/ssl_check.py
python -m py_compile modules/risk.py

# Usage

Run an audit against a hostname:

python auditor.py example.com

For local testing:

python auditor.py localhost

A typical audit performs:

1. Host resolution
2. Port scanning
3. HTTP security-header analysis
4. TLS/HTTPS analysis
5. Risk assessment
6. JSON report generation
7. HTML report generation

Example output:

Target: example.com

[*] Resolving host: example.com
[+] Host resolved
[+] IP address: 93.184.216.34

PORT SCAN
────────────────────────────────
22       SSH          CLOSED
53       DNS          CLOSED
80       HTTP         OPEN
443      HTTPS        OPEN
3306     MySQL        CLOSED
5432     PostgreSQL   CLOSED
8080     HTTP-Alt     CLOSED

HTTP SECURITY HEADERS
────────────────────────────────
[+] HTTP Status: 200
[!] Content-Security-Policy: MISSING
[+] X-Content-Type-Options: PRESENT
[+] X-Frame-Options: PRESENT
[+] Referrer-Policy: PRESENT
[+] Strict-Transport-Security: PRESENT

TLS / HTTPS ANALYSIS
────────────────────────────────
[+] TLS Version: TLSv1.3
[+] Modern TLS version
[+] Cipher: ...

AUDIT SUMMARY
────────────────────────────────
HIGH       0
MEDIUM     1
LOW        0
INFO       0

Risk Score: 3
Risk Level: MEDIUM

[+] Report saved: reports/example.com_report.json
[+] HTML report saved: reports/example.com_report.html

Viewing the HTML Report

The generated report is saved inside the "reports/" directory.

For example:

reports/example.com_report.html

From the project directory, start a local web server:

python -m http.server 8000

Then open:

http://localhost:8000

Navigate to:
reports/
and open the generated HTML report.

Risk Methodology
The risk engine separates severity from the numerical score.
Each finding has one of four severity levels:

Severity| Score| Meaning
INFO| 0| Informational result
LOW| 1| Minor security weakness
MEDIUM| 3| Security issue that should be reviewed
HIGH| 5| Significant security issue

The overall risk level is determined by the highest severity finding, rather than simply adding all scores together.
For example:
MEDIUM
LOW
LOW
LOW

results in:

Risk Level: MEDIUM

It does not become HIGH just because several low-severity findings exist.

Similarly:

HIGH
LOW
INFO

results in:

Risk Level: HIGH
The numerical score is retained as a quick indicator of the number and severity of findings, while the overall risk level reflects the most serious finding discovered.

Reports
Each audit produces two reports:

JSON
reports/example.com_report.json
The JSON report is intended to provide structured data that can be processed by other tools or used for future automation.

HTML
reports/example.com_report.html

The HTML report provides a more readable security assessment containing:
- Executive summary
- Risk score
- Risk level
- Port scan results
- HTTP security findings
- Remediation recommendations
- TLS information
- Certificate information

# Security Considerations
This tool is intended for authorized security testing and defensive auditing.
Only scan systems that you own or have explicit permission to assess.
The project does not attempt to exploit discovered vulnerabilities.

# Limitations
This is a learning project and is not intended to replace professional security assessment tools.
Current limitations include:
- Limited port list
- Basic service detection
- Basic HTTP header analysis
- Limited TLS testing
- No vulnerability exploitation
- No authenticated application testing
- No deep web application scanning
- Risk scoring is intentionally simple
These limitations are useful areas for future development.

# Future Improvements
Possible future additions include:
- Configurable port ranges
- Better service detection
- More HTTP security checks
- DNS security checks
- Better TLS configuration analysis
- Unit tests
- Command-line options
- Scan configuration files
- Improved HTML reporting
- Export to additional formats

# Why I Built This
I built this project to get more hands-on experience with Python, networking, HTTP, TLS, and security automation.
Rather than relying entirely on existing security scanners, I wanted to understand what happens underneath them and build the individual pieces myself.

Author
Ian AA
This project is part of my personal IT/security portfolio.
