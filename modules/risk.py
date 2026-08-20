SEVERITY_SCORES = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 5,
}

SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


def calculate_risk(findings):
    score = 0
    highest_severity = "INFO"

    for finding in findings:
        severity = finding.get("severity", "INFO")

        score += SEVERITY_SCORES.get(
            severity,
            0
        )

        if (
            SEVERITY_ORDER.get(severity, 0)
            >
            SEVERITY_ORDER.get(highest_severity, 0)
        ):
            highest_severity = severity

    return score, highest_severity


def print_summary(findings):
    score, risk_level = calculate_risk(findings)

    counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for finding in findings:
        severity = finding.get(
            "severity",
            "INFO"
        )

        if severity in counts:
            counts[severity] += 1

    print("\nAUDIT SUMMARY")
    print("────────────────────────────────")

    print(f"HIGH       {counts['HIGH']}")
    print(f"MEDIUM     {counts['MEDIUM']}")
    print(f"LOW        {counts['LOW']}")
    print(f"INFO       {counts['INFO']}")

    print()
    print(f"Risk Score: {score}")
    print(f"Risk Level: {risk_level}")

    return score, risk_level
