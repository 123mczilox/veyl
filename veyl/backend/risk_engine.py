"""Legacy standalone risk scorer; the browser API now uses app.scanner instead."""

def calculate_risk(message, url_results):
    """
    Calculate a preliminary risk score using message and URL indicators.

    This is a heuristic, not a verified probability that a message is a scam.
    """

    score = 0
    evidence = []

    # 1. Check for requests for sensitive information
    sensitive_terms = [
        "pin",
        "password",
        "passcode",
        "otp",
        "verification code",
        "bank details",
    ]

    message_lower = message.lower()

    for term in sensitive_terms:
        if term in message_lower:
            score += 3
            evidence.append(
                f"Requests or mentions sensitive information: {term}"
            )

    # 2. Check for urgency or threats
    urgency_terms = [
        "urgent",
        "immediately",
        "act now",
        "suspended",
        "blocked",
        "expire",
        "limited time",
    ]

    for term in urgency_terms:
        if term in message_lower:
            score += 2
            evidence.append(
                f"Contains urgency or threat language: {term}"
            )

    # 3. Use findings from our URL analyzer
    for result in url_results:
        for finding in result["findings"]:
            evidence.append(f"URL warning: {finding}")

            if "HTTP rather than HTTPS" in finding:
                score += 1

            elif "IPv4 address" in finding:
                score += 2

            elif "punycode" in finding.lower():
                score += 2

            elif "hostname is unusually long" in finding.lower():
                score += 1

            elif "many hostname components" in finding.lower():
                score += 1

    # 4. Convert the score into a preliminary risk category
    if score >= 7:
        risk_level = "high"
    elif score >= 3:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "score": score,
        "risk_level": risk_level,
        "evidence": evidence,
    }
