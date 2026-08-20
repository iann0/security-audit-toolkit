from datetime import datetime
from pathlib import Path
from html import escape


RECOMMENDATIONS = {
    "Content-Security-Policy": (
        "Implement a restrictive Content-Security-Policy "
        "appropriate for the application's resources."
    ),
    "X-Content-Type-Options": (
        "Set X-Content-Type-Options to 'nosniff' to "
        "reduce MIME-type sniffing risks."
    ),
    "X-Frame-Options": (
        "Set X-Frame-Options to DENY or SAMEORIGIN, "
        "or use an appropriate CSP frame-ancestors policy."
    ),
    "Referrer-Policy": (
        "Configure an appropriate Referrer-Policy such as "
        "strict-origin-when-cross-origin."
    ),
    "Strict-Transport-Security": (
        "Enable HSTS on HTTPS deployments after confirming "
        "that the application and required resources work "
        "correctly over HTTPS."
    ),
}


def get_risk_class(risk_level):
    return str(risk_level).lower()


def generate_html_report(
    target,
    ports,
    findings,
    score,
    risk_level,
    tls_results=None,
):
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    safe_target = (
        target
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
    )

    filename = reports_dir / f"{safe_target}_report.html"

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    risk_class = get_risk_class(risk_level)

    # --------------------------------------------------
    # PORT RESULTS
    # --------------------------------------------------

    port_rows = ""

    for port in ports or []:
        port_number = port.get("port", "")
        service = port.get("service", "")

        status = port.get("status")

        if status is None:
            status = (
                "OPEN"
                if port.get("open")
                else "CLOSED"
            )

        status = str(status).upper()

        status_class = (
            "open"
            if status == "OPEN"
            else "closed"
        )

        port_rows += (
            "<tr>"
            f"<td>{escape(str(port_number))}</td>"
            f"<td>{escape(str(service))}</td>"
            f'<td class="{status_class}">'
            f"{escape(status)}"
            "</td>"
            "</tr>"
        )

    if not port_rows:
        port_rows = (
            "<tr>"
            '<td colspan="3">'
            "No port results available."
            "</td>"
            "</tr>"
        )

    # --------------------------------------------------
    # HTTP SECURITY FINDINGS
    # --------------------------------------------------

    finding_rows = ""

    for finding in findings or []:
        header = finding.get(
            "header",
            "Unknown",
        )

        severity = finding.get(
            "severity",
            "INFO",
        )

        description = finding.get(
            "description",
            "",
        )

        recommendation = RECOMMENDATIONS.get(
            header,
            "Review this security finding and determine "
            "an appropriate remediation.",
        )

        finding_rows += (
            "<tr>"
            f"<td>{escape(str(header))}</td>"
            f'<td class="{str(severity).lower()}">'
            f"{escape(str(severity))}"
            "</td>"
            "<td>"
            f"{escape(str(description))}"
            "</td>"
            "<td>"
            f"{escape(str(recommendation))}"
            "</td>"
            "</tr>"
        )

    if not finding_rows:
        finding_rows = (
            "<tr>"
            '<td colspan="4">'
            "No security findings."
            "</td>"
            "</tr>"
        )

    # --------------------------------------------------
    # TLS RESULTS
    # --------------------------------------------------

    if tls_results:
        tls_status = tls_results.get("status")

        if tls_status == "success":
            certificate = tls_results.get(
                "certificate",
                {},
            )

            tls_version = tls_results.get(
                "tls_version",
                "Unknown",
            )

            cipher = tls_results.get(
                "cipher",
                "Unknown",
            )

            subject = certificate.get(
                "subject",
                "Unknown",
            )

            issuer = certificate.get(
                "issuer",
                "Unknown",
            )

            expiry = certificate.get(
                "expiry",
                "Unknown",
            )

            valid = certificate.get(
                "valid",
                "Unknown",
            )

            tls_html = (
                '<div class="tls-grid">'

                "<div>"
                "<strong>TLS Version</strong>"
                f"<span>{escape(str(tls_version))}</span>"
                "</div>"

                "<div>"
                "<strong>Cipher</strong>"
                f"<span>{escape(str(cipher))}</span>"
                "</div>"

                "<div>"
                "<strong>Certificate Subject</strong>"
                f"<span>{escape(str(subject))}</span>"
                "</div>"

                "<div>"
                "<strong>Certificate Issuer</strong>"
                f"<span>{escape(str(issuer))}</span>"
                "</div>"

                "<div>"
                "<strong>Certificate Expiry</strong>"
                f"<span>{escape(str(expiry))}</span>"
                "</div>"

                "<div>"
                "<strong>Certificate Valid</strong>"
                f"<span>{escape(str(valid))}</span>"
                "</div>"

                "</div>"
            )

        else:
            error = tls_results.get(
                "error",
                "Unknown error",
            )

            tls_html = (
                '<div class="error">'
                "<strong>TLS analysis failed</strong>"
                "<p>"
                f"{escape(str(error))}"
                "</p>"
                "</div>"
            )

    else:
        tls_html = (
            "<p>No TLS results available.</p>"
        )

    # --------------------------------------------------
    # HTML
    # --------------------------------------------------

    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <meta name="description"
          content="Security audit report">

    <title>Security Audit Report</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            padding: 40px;

            background: #0b0f14;
            color: #d8dee9;

            font-family:
                Arial,
                Helvetica,
                sans-serif;

            line-height: 1.5;
        }

        .container {
            max-width: 1200px;
            margin: auto;
        }

        header {
            margin-bottom: 30px;
        }

        h1 {
            margin-bottom: 8px;
            font-size: 32px;
        }

        h2 {
            margin-top: 0;
            margin-bottom: 20px;
        }

        .subtitle {
            color: #8b949e;
            margin-bottom: 4px;
        }

        .card {
            background: #111820;

            border: 1px solid #27313d;

            border-radius: 10px;

            padding: 24px;

            margin-bottom: 24px;
        }

        .summary {
            display: grid;

            grid-template-columns:
                repeat(
                    auto-fit,
                    minmax(180px, 1fr)
                );

            gap: 16px;
        }

        .metric {
            background: #0d131a;

            border: 1px solid #27313d;

            border-radius: 8px;

            padding: 20px;
        }

        .metric strong {
            display: block;

            color: #8b949e;

            font-size: 13px;

            margin-bottom: 8px;
        }

        .metric span {
            font-size: 24px;
            font-weight: bold;
        }

        .risk {
            font-weight: bold;
            text-transform: uppercase;
        }

        .risk.high {
            color: #ff6b6b;
        }

        .risk.medium {
            color: #ffa94d;
        }

        .risk.low {
            color: #69db7c;
        }

        .risk.info {
            color: #74c0fc;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th,
        td {
            text-align: left;

            padding: 13px;

            border-bottom:
                1px solid #27313d;

            vertical-align: top;
        }

        th {
            color: #8b949e;

            font-size: 13px;

            text-transform: uppercase;
        }

        .open {
            color: #69db7c;
            font-weight: bold;
        }

        .closed {
            color: #8b949e;
        }

        .high {
            color: #ff6b6b;
            font-weight: bold;
        }

        .medium {
            color: #ffa94d;
            font-weight: bold;
        }

        .low {
            color: #69db7c;
            font-weight: bold;
        }

        .info {
            color: #74c0fc;
            font-weight: bold;
        }

        .tls-grid {
            display: grid;

            grid-template-columns:
                repeat(
                    auto-fit,
                    minmax(280px, 1fr)
                );

            gap: 15px;
        }

        .tls-grid div {
            background: #0d131a;

            border: 1px solid #27313d;

            border-radius: 8px;

            padding: 16px;
        }

        .tls-grid strong {
            display: block;

            color: #8b949e;

            margin-bottom: 8px;
        }

        .tls-grid span {
            word-break: break-word;
        }

        .error {
            padding: 15px;

            border-left:
                4px solid #ff6b6b;

            background: #1a1012;

            border-radius: 4px;
        }

        footer {
            color: #66717f;

            font-size: 12px;

            margin-top: 30px;

            padding-top: 20px;

            border-top:
                1px solid #27313d;
        }

        @media (max-width: 700px) {
            body {
                padding: 20px;
            }

            h1 {
                font-size: 26px;
            }

            table {
                display: block;
                overflow-x: auto;
            }

            th,
            td {
                min-width: 140px;
            }
        }
    </style>
</head>

<body>

<div class="container">

    <header>
        <h1>Security Audit Report</h1>

        <div class="subtitle">
            Target:
            <strong>""" + escape(str(target)) + """</strong>
        </div>

        <div class="subtitle">
            Generated:
            """ + escape(timestamp) + """
        </div>
    </header>

    <section class="card">

        <h2>Executive Summary</h2>

        <div class="summary">

            <div class="metric">
                <strong>Risk Score</strong>
                <span>""" + escape(str(score)) + """</span>
            </div>

            <div class="metric">
                <strong>Risk Level</strong>
                <span class="risk """ + risk_class + """">
                    """ + escape(str(risk_level)) + """
                </span>
            </div>

            <div class="metric">
                <strong>Findings</strong>
                <span>""" + str(len(findings or [])) + """</span>
            </div>

            <div class="metric">
                <strong>Ports Tested</strong>
                <span>""" + str(len(ports or [])) + """</span>
            </div>

        </div>

    </section>

    <section class="card">

        <h2>Port Scan</h2>

        <table>

            <thead>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Status</th>
                </tr>
            </thead>

            <tbody>
                """ + port_rows + """
            </tbody>

        </table>

    </section>

    <section class="card">

        <h2>HTTP Security Findings</h2>

        <table>

            <thead>
                <tr>
                    <th>Header</th>
                    <th>Severity</th>
                    <th>Description</th>
                    <th>Recommendation</th>
                </tr>
            </thead>

            <tbody>
                """ + finding_rows + """
            </tbody>

        </table>

    </section>

    <section class="card">

        <h2>TLS / HTTPS Analysis</h2>

        """ + tls_html + """

    </section>

    <footer>
        Generated by
        <strong>Security Audit Toolkit</strong>.

        <br>

        Intended for authorized security testing
        and defensive auditing.
    </footer>

</div>

</body>
</html>
"""

    # --------------------------------------------------
    # WRITE REPORT
    # --------------------------------------------------

    with open(
        filename,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(html)

    print(
        f"[+] HTML report saved: {filename}"
    )

    return filename
