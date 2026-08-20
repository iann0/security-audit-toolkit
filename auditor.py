#!/usr/bin/env python3

import argparse
import socket
import time

from modules.ports import scan_ports
from modules.headers import check_headers
from modules.risk import print_summary
from modules.report import save_report
from modules.ssl_check import check_tls
from modules.html_report import generate_html_report

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"


def banner():
    print(f"""
{GREEN}
╔══════════════════════════════════════╗
║       SECURITY AUDIT TOOLKIT         ║
╚══════════════════════════════════════╝
{RESET}
""")


def check_host(target):
    print(f"[*] Resolving host: {target}")

    try:
        ip = socket.gethostbyname(target)

        print(f"{GREEN}[+] Host resolved{RESET}")
        print(f"[+] IP address: {ip}")

        return ip

    except socket.gaierror:
        print(f"{RED}[-] Could not resolve host{RESET}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description="Security Audit Toolkit"
    )

    parser.add_argument(
        "target",
        help="Authorized IP address or hostname to audit"
    )

    args = parser.parse_args()

    banner()

    print(f"Target: {args.target}\n")

    host = check_host(args.target)

    if host:
        port_results = scan_ports(host)

        findings = check_headers(
        f"http://{args.target}"
        )

        tls_results = check_tls(args.target)

        score, risk_level = print_summary(findings)

        save_report(
          args.target,
          port_results,
          findings,
          score,
          risk_level,
          tls_results
        )
        generate_html_report(
          args.target,
          port_results,
          findings,
          score,
          risk_level,
          tls_results
        )

if __name__ == "__main__":
    main()
