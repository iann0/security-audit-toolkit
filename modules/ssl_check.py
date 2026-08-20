import socket
import ssl
from datetime import datetime, timezone


def check_tls(host, port=443):
    print("\nTLS / HTTPS ANALYSIS")
    print("────────────────────────────────")

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (host, port),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=host
            ) as tls_socket:

                version = tls_socket.version()
                cipher = tls_socket.cipher()
                certificate = tls_socket.getpeercert()

                print(f"[+] TLS Version: {version}")

                if version == "TLSv1.3":
                    print("[+] Modern TLS version")
                elif version == "TLSv1.2":
                    print("[+] Supported TLS version")
                else:
                    print(
                        f"[!] Review TLS version: {version}"
                    )

                cipher_name = None

                if cipher:
                    cipher_name = cipher[0]
                    print(f"[+] Cipher: {cipher_name}")

                subject_name = "Unknown"
                issuer_name = "Unknown"
                expiry_iso = None
                certificate_valid = None

                if certificate:
                    subject = dict(
                        item[0]
                        for item in certificate.get("subject", ())
                    )

                    issuer = dict(
                        item[0]
                        for item in certificate.get("issuer", ())
                    )

                    subject_name = subject.get(
                        "commonName",
                        "Unknown"
                    )

                    issuer_name = issuer.get(
                        "commonName",
                        "Unknown"
                    )

                    print(
                        "[+] Certificate Subject: "
                        f"{subject_name}"
                    )

                    print(
                        "[+] Certificate Issuer: "
                        f"{issuer_name}"
                    )

                    expiry = certificate.get("notAfter")

                    if expiry:
                        expiry_date = datetime.strptime(
                            expiry,
                            "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)

                        expiry_iso = expiry_date.isoformat()

                        print(
                            "[+] Certificate Expiry: "
                            f"{expiry_iso}"
                        )

                        if expiry_date < datetime.now(
                            timezone.utc
                        ):
                            certificate_valid = False
                            print(
                                "[HIGH] Certificate has expired"
                            )
                        else:
                            certificate_valid = True
                            print(
                                "[+] Certificate is currently valid"
                            )

                return {
                    "status": "success",
                    "tls_version": version,
                    "cipher": cipher_name,
                    "certificate": {
                        "subject": subject_name,
                        "issuer": issuer_name,
                        "expiry": expiry_iso,
                        "valid": certificate_valid
                    }
                }

    except ssl.SSLCertVerificationError as error:
        print(
            "[HIGH] Certificate verification failed"
        )
        print(f"      {error}")

        return {
            "status": "certificate_error",
            "error": str(error)
        }

    except (
        ssl.SSLError,
        socket.timeout,
        OSError
    ) as error:

        print(
            f"[-] HTTPS connection failed: {error}"
        )

        return {
            "status": "connection_error",
            "error": str(error)
        }
