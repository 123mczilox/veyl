"""Passive URL analysis. The submitted destination is never fetched."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen


SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "ow.ly", "buff.ly", "cutt.ly",
    "shorturl.at", "rb.gy", "rebrand.ly", "lnkd.in",
}
PUBLIC_TUNNEL_DOMAINS = ("loca.lt", "localtunnel.me")
LURE_WORDS = {
    "account", "billing", "confirm", "login", "password", "payment", "secure",
    "signin", "unlock", "update", "verify", "wallet",
}
BRAND_DOMAINS = {
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.de"),
    "apple": ("apple.com",),
    "facebook": ("facebook.com", "fb.com"),
    "google": ("google.com", "google.co.uk"),
    "instagram": ("instagram.com",),
    "microsoft": ("microsoft.com", "microsoftonline.com", "live.com"),
    "netflix": ("netflix.com",),
    "paypal": ("paypal.com",),
}
REDIRECT_KEYS = {"continue", "dest", "destination", "next", "redirect", "return", "target", "url"}
URGENCY_PATTERN = re.compile(
    r"\b(?:urgent|act now|immediately|right away|within\s+\d+\s+(?:minutes?|hours?|days?)|"
    r"last chance|final (?:notice|warning)|expires? today|account (?:will be|has been) (?:suspended|locked))\b",
    re.IGNORECASE,
)
SENSITIVE_ACTION_PATTERN = re.compile(
    r"\b(?:password|one[- ]time (?:code|passcode)|verification code|security code|cvv|card number|"
    r"bank details|payment|fee is due|pay (?:within|now)|confirm your (?:account|identity)|"
    r"verify your (?:account|identity)|sign in|log in)\b",
    re.IGNORECASE,
)


class ScanInputError(ValueError):
    """Raised when an input is malformed or outside the passive scanner's scope."""


def _validate_and_normalize(raw_url: str) -> tuple[str, str, bool, int | None]:
    value = raw_url.strip()
    if not value:
        raise ScanInputError("Paste a URL to scan.")
    if len(value) > 4096:
        raise ScanInputError("This URL is too long to analyze (maximum 4,096 characters).")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ScanInputError("The URL contains control characters.")
    if any(char.isspace() for char in value):
        raise ScanInputError("The URL contains spaces. Check the link and try again.")

    if value.startswith("//"):
        value = f"https:{value}"
    elif not re.match(r"^https?://", value, re.IGNORECASE):
        if "://" in value:
            raise ScanInputError("Only http:// and https:// links can be analyzed.")
        value = f"https://{value}"

    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise ScanInputError("The URL has an invalid host or port.") from exc

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ScanInputError("Only http:// and https:// links can be analyzed.")
    if not parts.netloc or not parts.hostname:
        raise ScanInputError("Enter a complete URL, including its domain name.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc.rsplit(":", 1)[0]:
        raise ScanInputError("URLs containing embedded usernames or passwords are not accepted.")

    host = parts.hostname.rstrip(".").lower()
    if not host:
        raise ScanInputError("The URL does not contain a valid host name.")

    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        ip = None

    if ip is None and re.fullmatch(r"[0-9.]+", host):
        raise ScanInputError("Ambiguous numeric hosts cannot be analyzed safely.")

    if ip is not None:
        if not ip.is_global:
            raise ScanInputError("Private, local, and reserved IP addresses cannot be analyzed.")
        ascii_host = ip.compressed
        is_ip = True
    else:
        try:
            ascii_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ScanInputError("The domain name could not be normalized safely.") from exc
        if ascii_host == "localhost" or ascii_host.endswith((".localhost", ".local", ".internal", ".test")):
            raise ScanInputError("Local and internal host names cannot be analyzed.")
        if len(ascii_host) > 253 or "." not in ascii_host:
            raise ScanInputError("Enter a public domain name rather than a local host name.")
        labels = ascii_host.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.fullmatch(r"[a-z0-9-]+", label)
            for label in labels
        ):
            raise ScanInputError("The domain name has an invalid format.")
        is_ip = False

    display_host = f"[{ascii_host}]" if is_ip and ":" in ascii_host else ascii_host
    netloc = display_host
    if port is not None and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        netloc = f"{display_host}:{port}"
    normalized = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return normalized, ascii_host, is_ip, port


def _finding(title: str, detail: str, points: int, severity: str) -> dict[str, object]:
    return {"title": title, "detail": detail, "points": points, "severity": severity}


def _pattern_findings(url: str, host: str, is_ip: bool, port: int | None) -> list[dict[str, object]]:
    parts = urlsplit(url)
    findings: list[dict[str, object]] = []

    if is_ip:
        findings.append(_finding(
            "Direct IP address",
            "The link uses a numeric address instead of a recognizable domain. This can make the destination harder to identify.",
            26,
            "medium",
        ))

    labels = host.split(".")
    if any(label.startswith("xn--") for label in labels):
        findings.append(_finding(
            "Internationalized domain encoding",
            "The domain contains a Punycode label. This can be legitimate, but similar-looking characters are sometimes used to imitate another site.",
            22,
            "medium",
        ))

    if len(labels) >= 5:
        findings.append(_finding(
            "Unusually deep subdomain",
            f"The host has {len(labels)} labels, which can obscure the registered destination domain.",
            12,
            "low",
        ))

    if host in SHORTENERS:
        findings.append(_finding(
            "URL shortener",
            "The submitted host is a link-shortening service, so this passive scan cannot see the final destination.",
            18,
            "medium",
        ))

    tunnel_domain = next(
        (domain for domain in PUBLIC_TUNNEL_DOMAINS if host == domain or host.endswith(f".{domain}")),
        None,
    )
    if tunnel_domain:
        findings.append(_finding(
            "Public development tunnel host",
            "This host uses a public tunnel service that can expose a local development server through a shareable URL. That can be legitimate, but the service does not identify who controls this specific link.",
            18,
            "medium",
        ))

    words = set(re.findall(r"[a-z0-9]+", f"{host} {parts.path} {parts.query}".lower()))
    matched_lures = sorted(words & LURE_WORDS)
    if matched_lures:
        findings.append(_finding(
            "Account or verification language",
            f"The URL includes terms often used in credential prompts: {', '.join(matched_lures[:4])}.",
            min(16, 7 + len(matched_lures) * 3),
            "low",
        ))

    host_labels = set(labels[:-1])
    for brand, official_domains in BRAND_DOMAINS.items():
        if brand in host_labels or any(label.startswith(f"{brand}-") or label.endswith(f"-{brand}") for label in host_labels):
            if not any(host == domain or host.endswith(f".{domain}") for domain in official_domains):
                findings.append(_finding(
                    "Brand name outside its usual domain",
                    f"The host includes “{brand}” but does not end in a domain listed for that brand in this prototype's small comparison set. Verify the sender and destination independently.",
                    26,
                    "high",
                ))
                break

    redirect_hosts: set[str] = set()
    for key, value in parse_qsl(parts.query, keep_blank_values=False):
        if key.lower() not in REDIRECT_KEYS or not value.lower().startswith(("http://", "https://")):
            continue
        try:
            redirect_host = (urlsplit(value).hostname or "").encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError):
            continue
        if redirect_host and redirect_host != host:
            redirect_hosts.add(redirect_host)
    if redirect_hosts:
        findings.append(_finding(
            "External redirect parameter",
            "A query parameter points to a different host. The destination may change after the link is used; this scanner does not follow it.",
            14,
            "medium",
        ))

    if parts.scheme.lower() == "http":
        findings.append(_finding(
            "Unencrypted connection",
            "The link uses HTTP rather than HTTPS. This does not prove the site is malicious, but the connection is not protected by TLS.",
            6,
            "low",
        ))

    expected_port = 443 if parts.scheme.lower() == "https" else 80
    if port is not None and port != expected_port:
        findings.append(_finding(
            "Non-standard web port",
            f"The destination uses port {port}, rather than the usual port {expected_port} for this scheme.",
            10,
            "low",
        ))

    if len(url) > 250:
        findings.append(_finding(
            "Long URL",
            "The link is unusually long, which can make its destination and parameters harder to inspect.",
            6,
            "low",
        ))

    if len(re.findall(r"%[0-9a-fA-F]{2}", url)) >= 8:
        findings.append(_finding(
            "Heavily encoded URL",
            "Many URL characters are percent-encoded, making the path or query harder to read at a glance.",
            8,
            "low",
        ))

    return findings


def _message_findings(message: str) -> list[dict[str, object]]:
    """Identify a couple of explainable message signals without sending text elsewhere."""
    text = re.sub(r"\s+", " ", message).strip()
    if not text:
        return []

    findings: list[dict[str, object]] = []
    if URGENCY_PATTERN.search(text):
        findings.append(_finding(
            "Urgency or deadline language",
            "The message pressures the recipient to act quickly. Urgency can be used to discourage careful checking, though it is not proof of fraud.",
            8,
            "low",
        ))
    if SENSITIVE_ACTION_PATTERN.search(text):
        findings.append(_finding(
            "Request involving account or payment details",
            "The message mentions credentials, identity checks, or payment. Do not share passwords or verification codes through a link in a message.",
            14,
            "medium",
        ))
    return findings


def _check_safe_browsing(url: str) -> tuple[str, str | None]:
    if not SAFE_BROWSING_KEY:
        return "not_configured", None

    body = {
        "client": {"clientId": "linkguard-prototype", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    query = urlencode({"key": SAFE_BROWSING_KEY})
    request = Request(
        f"{SAFE_BROWSING_ENDPOINT}?{query}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=4) as response:
            result = json.loads(response.read(256_000).decode("utf-8"))
        matches = result.get("matches", []) if isinstance(result, dict) else []
        if matches:
            kinds = sorted({str(match.get("threatType", "UNKNOWN")).replace("_", " ").title() for match in matches})
            return "match", ", ".join(kinds)
        return "clean", None
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return "unavailable", None


def analyze_url(raw_url: str, message: str = "") -> dict[str, object]:
    normalized, host, is_ip, port = _validate_and_normalize(raw_url)
    findings = _pattern_findings(normalized, host, is_ip, port) + _message_findings(message)
    rule_points = min(100, sum(int(item["points"]) for item in findings))
    severity_floor = max(
        ( {"info": 0, "low": 0, "medium": 35, "high": 70}.get(str(item["severity"]), 0) for item in findings ),
        default=0,
    )
    pattern_score = max(rule_points, severity_floor)
    intel_status, intel_detail = _check_safe_browsing(normalized)

    if intel_status == "match":
        risk_score = max(pattern_score, 92)
        verdict = "Known threat match"
        level = "high"
        findings.append(_finding(
            "Threat intelligence match",
            f"Google Safe Browsing reported a match for {intel_detail or 'a known threat'}.",
            92,
            "high",
        ))
    elif pattern_score >= 70:
        risk_score, verdict, level = pattern_score, "High risk signals", "high"
    elif pattern_score >= 35:
        risk_score, verdict, level = pattern_score, "Suspicious signals", "medium"
    elif intel_status == "clean":
        risk_score, verdict, level = pattern_score, "No known threat match", "low"
    else:
        risk_score, verdict, level = pattern_score, "Inconclusive", "unknown"

    if level == "high":
        recommendation = "Avoid opening this link or entering information. If it came from someone you know, verify it with them through a separate channel."
    elif any(item["title"] == "Public development tunnel host" for item in findings):
        recommendation = "This link uses a public development tunnel, which can be legitimate but is difficult to verify from the URL alone. Confirm who sent it and why through a separate channel before opening it."
    elif level == "medium":
        recommendation = "Treat the link cautiously. Go to the service using a saved bookmark or type its known address yourself."
    elif intel_status == "clean":
        recommendation = "No known threat match was returned, but that does not prove the destination is safe. Verify the sender and expected destination."
    else:
        recommendation = "There is not enough evidence for a verdict. Do not treat this result as proof of safety; verify the sender and destination independently."

    if not findings:
        findings = [{
            "title": "No obvious URL patterns found",
            "detail": "The passive rules in this prototype did not identify a suspicious pattern. The destination page was not opened.",
            "points": 0,
            "severity": "info",
        }]

    intel_labels = {
        "not_configured": "Not configured",
        "unavailable": "Temporarily unavailable",
        "clean": "No match returned",
        "match": "Match found",
    }
    return {
        "submitted_url": normalized,
        "host": host,
        "verdict": verdict,
        "level": level,
        "risk_score": risk_score,
        "score_label": "Rule signal points, not a probability",
        "findings": findings,
        "recommendation": recommendation,
        "threat_intelligence": {
            "provider": "Google Safe Browsing",
            "status": intel_status,
            "label": intel_labels.get(intel_status, "Unknown"),
            "detail": intel_detail,
        },
        "analysis_mode": "Passive URL and message checks; destination not opened",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
