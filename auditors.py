#!/usr/bin/env python3

import argparse
import socket
import time


GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
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
    print(f"[*] Checking host: {target}")

    try:
        ip = socket.gethostbyname(target)

        start = time.perf_counter()

        with socket.create_connection((ip, 80), timeout=2):
            pass

        latency = (time.perf_counter() - start) * 1000

        print(f"{GREEN}[+] Host reachable{RESET}")
        print(f"[+] IP address: {ip}")
        print(f"[+] Response time: {latency:.2f} ms")

        return True

    except (socket.timeout, ConnectionRefusedError, OSError):
        print(f"{RED}[-] Host could not be reached{RESET}")
        return False


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

    check_host(args.target)


if __name__ == "__main__":
    main()
