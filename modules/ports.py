import socket


COMMON_PORTS = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
}


def scan_port(host, port, timeout=0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_ports(host):
    results = []

    print("\nPORT SCAN")
    print("────────────────────────────────")

    for port, service in COMMON_PORTS.items():
        is_open = scan_port(host, port)

        status = "OPEN" if is_open else "CLOSED"

        print(f"{port:<8} {service:<12} {status}")

        results.append({
            "port": port,
            "service": service,
            "open": is_open,
        })

    return results
