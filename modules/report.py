import json
from datetime import datetime
from pathlib import Path


def save_report(
    target,
    ports,
    findings,
    score,
    risk_level,
    tls_results=None
):
    report = {
        "audit": {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "risk_score": score,
            "risk_level": risk_level,

            "ports": ports,

            "findings": findings,

            "tls": tls_results
        }
    }

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

    filename = (
        reports_dir /
        f"{safe_target}_report.json"
    )

    with open(filename, "w") as file:
        json.dump(
            report,
            file,
            indent=4
        )

    print(
        f"\n[+] Report saved: {filename}"
    )

    return filename
