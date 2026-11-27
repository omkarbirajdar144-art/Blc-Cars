import ipaddress
import socket
import time
import requests
from urllib.parse import urlparse


def _is_public_ip(value):
    address = ipaddress.ip_address(value)
    return address.is_global



def build_fix_suggestions(https, security_headers):
    """Return practical suggestions based only on checks actually performed."""
    suggestions = []
    if not https:
        suggestions.append({
            "issue": "HTTPS was not confirmed",
            "risk": "Traffic may not be protected by HTTPS.",
            "fix": "Configure a valid TLS certificate and redirect HTTP traffic to HTTPS."
        })

    header_fixes = {
        "Content-Security-Policy": "Create a Content-Security-Policy suited to the site's scripts, styles, images and other resources.",
        "X-Content-Type-Options": "Add the response header X-Content-Type-Options: nosniff.",
        "X-Frame-Options": "Set X-Frame-Options to DENY or SAMEORIGIN, or use frame-ancestors in Content-Security-Policy.",
        "Strict-Transport-Security": "After confirming HTTPS works across the site, configure a suitable Strict-Transport-Security policy."
    }
    for header, present in (security_headers or {}).items():
        if not present and header in header_fixes:
            suggestions.append({
                "issue": f"Missing {header}",
                "risk": "A recommended browser security control was not detected in the HTTP response.",
                "fix": header_fixes[header]
            })

    if not suggestions:
        suggestions.append({
            "issue": "No issue found in the checks performed",
            "risk": "This limited scan cannot guarantee that the website is secure.",
            "fix": "Keep software updated and perform regular authorized security reviews."
        })
    return suggestions


def scan_target(target, progress_callback=None):
    def emit(message, percent):
        if progress_callback:
            progress_callback(message, percent)

    original = target.strip()
    try:
        emit("Validating target format", 5)
        candidate = original if "://" in original else "https://" + original
        parsed = urlparse(candidate)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Use a valid public http/https website or domain.")
        if parsed.username or parsed.password:
            raise ValueError("URLs containing usernames or passwords are not allowed.")

        hostname = parsed.hostname
        emit("Resolving DNS hostname", 18)
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None, socket.AF_INET)})
        if not addresses:
            raise ValueError("No IPv4 address found for this hostname.")
        if any(not _is_public_ip(address) for address in addresses):
            raise ValueError("Private, local, or reserved network targets are blocked.")
        ip = addresses[0]

        emit("Connecting to website", 38)
        start = time.time()
        response = requests.get(
            candidate, timeout=8, allow_redirects=False,
            headers={"User-Agent": "CyberGuard-Educational-Scanner/3.0"}
        )
        response_time = round((time.time() - start) * 1000, 2)
        emit("Reviewing HTTP response and security headers", 62)

        https = parsed.scheme == "https" and response.url.startswith("https://")
        headers = response.headers
        security_headers = {
            "Content-Security-Policy": bool(headers.get("Content-Security-Policy")),
            "X-Content-Type-Options": bool(headers.get("X-Content-Type-Options")),
            "X-Frame-Options": bool(headers.get("X-Frame-Options")),
            "Strict-Transport-Security": bool(headers.get("Strict-Transport-Security"))
        }
        score = (40 if https else 0) + (20 if response.status_code < 400 else 0)
        score += sum(10 for present in security_headers.values() if present)
        status_text = ("Good Security Posture" if score >= 80 else
                       "Needs Improvement" if score >= 50 else "Security Warnings Found")
        emit("Security header review complete", 72)
        return {
            "target": original, "hostname": hostname, "ip": ip,
            "status": "Website reachable", "http_status": response.status_code,
            "response_time": response_time, "https": https,
            "security_headers": security_headers, "score": score,
            "recommendations": build_fix_suggestions(https, security_headers),
            "security_status": status_text,
            "redirect_detected": 300 <= response.status_code < 400
        }
    except (requests.RequestException, socket.gaierror, ValueError, OSError) as exc:
        emit("Target validation or connection failed", 100)
        return {
            "target": original, "hostname": "Not available", "ip": "Not available",
            "status": "Scan could not be completed", "http_status": "N/A",
            "response_time": "N/A", "https": False, "security_headers": {},
            "score": 0, "security_status": str(exc)[:180],
            "recommendations": [{"issue": "Scan not completed", "risk": "No reliable security findings are available.", "fix": "Check the URL and network connection, then run the scan again."}]
        }
