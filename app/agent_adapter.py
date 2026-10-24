"""Privacy-limited input contract for the optional AI review.

The agent receives the hostname and structured scan evidence only. URL paths,
query values, fragments, and original message text are excluded; the destination
is never fetched by this integration.
"""

from typing import Any


def evidence_for_agent(report: dict[str, Any]) -> dict[str, Any]:
    """Return a compact payload without paths, query values, or message text."""
    return {
        "hostname": report["host"],
        "verdict": report["verdict"],
        "risk_score": report["risk_score"],
        "score_label": report["score_label"],
        "findings": [
            {"title": item["title"], "detail": item["detail"], "severity": item["severity"]}
            for item in report["findings"]
        ],
        "threat_intelligence": report["threat_intelligence"],
        "recommendation": report["recommendation"],
    }
