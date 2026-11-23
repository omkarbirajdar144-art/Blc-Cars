import ipaddress
import re
from urllib.parse import urlparse, unquote

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly",
    "rb.gy", "ow.ly", "buff.ly", "shorturl.at"
}
SUSPICIOUS_WORDS = {
    "login", "verify", "account", "secure", "update", "password",
    "wallet", "banking", "free-gift", "claim-prize", "support"
}


def check_url(raw_url):
    """Perform offline URL structure checks only; does not visit the submitted URL."""
    value = (raw_url or "").strip()
    if not value or len(value) > 2048:
        raise ValueError("Enter a URL between 1 and 2048 characters.")

    candidate = value if "://" in value else "https://" + value
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded usernames or passwords are not accepted.")

    host = parsed.hostname.rstrip(".").lower()
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        raise ValueError("The hostname contains unsupported characters.")

    checks = []
    risk_points = 0

    def add(name, status, detail, points=0):
        nonlocal risk_points
        risk_points += points
        checks.append({"name": name, "status": status, "detail": detail})

    if parsed.scheme.lower() == "https":
        add("HTTPS scheme", "PASS", "The link uses HTTPS.")
    else:
        add("HTTPS scheme", "WARNING", "The link uses HTTP, so transport encryption is not indicated.", 15)

    try:
        ipaddress.ip_address(host)
        add("IP address host", "WARNING", "The link uses an IP address instead of a domain name.", 15)
    except ValueError:
        add("Domain format", "PASS", "A domain name is present.")

    if host.startswith("xn--") or ".xn--" in host:
        add("Internationalized domain", "WARNING", "Punycode can make look-alike domains harder to recognize.", 20)
    else:
        add("Internationalized domain", "PASS", "No punycode label detected.")

    if "@" in parsed.netloc:
        add("URL user-info", "WARNING", "The URL contains an @ character in its authority section.", 20)
    else:
        add("URL user-info", "PASS", "No embedded user-info detected.")

    if host in SHORTENERS:
        add("URL shortener", "REVIEW", "This is a shortened link; its final destination has not been expanded.", 15)
    else:
        add("URL shortener", "PASS", "The hostname is not in the built-in shortener list.")

    lowered = unquote((parsed.path + " " + parsed.query).lower())
    matched = sorted(word for word in SUSPICIOUS_WORDS if word in lowered)
    if matched:
        add("Sensitive-action keywords", "REVIEW",
            "The path or query contains: " + ", ".join(matched) + ".", 10)
    else:
        add("Sensitive-action keywords", "PASS", "No common sensitive-action keywords detected.")

    if len(host) > 45 or host.count(".") >= 5 or "--" in host:
        add("Hostname pattern", "REVIEW", "The hostname has an unusual length or structure.", 10)
    else:
        add("Hostname pattern", "PASS", "No basic unusual-hostname pattern detected.")

    if parsed.port and parsed.port not in (80, 443):
        add("Non-standard port", "REVIEW", "The link specifies a non-standard web port.", 10)
    else:
        add("Web port", "PASS", "No unusual explicit web port detected.")

    score = max(0, 100 - min(risk_points, 100))
    if score >= 85:
        verdict = "Lower warning level"
    elif score >= 60:
        verdict = "Review this link carefully"
    else:
        verdict = "Higher warning level"

    return {
        "input": value,
        "hostname": host,
        "scheme": parsed.scheme.lower(),
        "risk_score": score,
        "verdict": verdict,
        "checks": checks,
        "disclaimer": "This is an offline heuristic check, not a live reputation lookup. It does not open the link, follow redirects, inspect page content, or guarantee safety."
    }
