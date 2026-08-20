import requests


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "description": "Helps mitigate XSS and other content injection attacks."
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "description": "Helps prevent MIME-type sniffing."
    },
    "X-Frame-Options": {
        "severity": "LOW",
        "description": "Helps protect against clickjacking."
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls how much referrer information browsers send."
    },
    "Strict-Transport-Security": {
        "severity": "INFO",
        "description": "Enforces HTTPS connections."
    }
}


def check_headers(url):
    print("\nHTTP SECURITY HEADERS")
    print("────────────────────────────────")

    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True
        )

        print(f"[+] HTTP Status: {response.status_code}")
        print(f"[+] Final URL: {response.url}\n")

        findings = []

        for header, details in SECURITY_HEADERS.items():

            if header in response.headers:
                print(f"[+] {header}: PRESENT")

            else:
                severity = details["severity"]

                print(
                    f"[{severity}] {header}: MISSING"
                )

                findings.append({
                    "header": header,
                    "severity": severity,
                    "description": details["description"]
                })

        return findings

    except requests.RequestException as error:
        print(f"[-] HTTP check failed: {error}")
        return []
