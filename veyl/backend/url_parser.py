"""Legacy standalone parser; the browser API now uses app.scanner instead."""

import re
from urllib.parse import urlparse


def extract_urls(message):
    """
    Extract URLs from a text message.
    """

    pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'

    urls = re.findall(pattern, message, flags=re.IGNORECASE)

    # Remove common punctuation from the end of extracted URLs.
    cleaned_urls = [
        url.rstrip(".,!?;:)")
        for url in urls
    ]

    return cleaned_urls


def analyze_url(url):
    """
    Inspect a URL for suspicious characteristics.
    Does not open or visit the URL.
    """

    normalized_url = url

    if normalized_url.lower().startswith("www."):
        normalized_url = "http://" + normalized_url

    parsed = urlparse(normalized_url)

    hostname = parsed.hostname
    findings = []

    if not hostname:
        return {
            "url": url,
            "hostname": None,
            "findings": ["Could not determine the hostname"],
            "risk_indicators": len(findings) + 1,
        }

    hostname = hostname.lower()

    # HTTP does not encrypt the connection.
    if parsed.scheme.lower() == "http":
        findings.append("Uses HTTP rather than HTTPS")

    # IP addresses are sometimes used instead of recognizable domains.
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname):
        findings.append("Uses an IPv4 address instead of a domain name")

    # User information before @ can disguise the actual destination.
    if "@" in parsed.netloc:
        findings.append("Contains an @ symbol in the network location")

    # Long hostnames may warrant additional inspection.
    if len(hostname) > 50:
        findings.append("Hostname is unusually long")

    # Punycode can represent internationalized domain names.
    if "xn--" in hostname:
        findings.append("Contains a punycode hostname")

    # Many subdomains can make a URL harder to read.
    if len(hostname.split(".")) >= 5:
        findings.append("Contains many hostname components")

    return {
        "url": url,
        "hostname": hostname,
        "findings": findings,
        "risk_indicators": len(findings),
    }


def analyze_message_urls(message):
    """
    Extract and inspect every URL found in a message.
    """

    urls = extract_urls(message)

    return [
        analyze_url(url)
        for url in urls
    ]
