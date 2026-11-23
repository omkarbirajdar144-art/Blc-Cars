import ipaddress
import socket
import time
import requests
from urllib.parse import urlparse


def _is_public_ip(value):
    address = ipaddress.ip_address(value)
    return address.is_global


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
            "security_status": status_text,
            "redirect_detected": 300 <= response.status_code < 400
        }
    except (requests.RequestException, socket.gaierror, ValueError, OSError) as exc:
        emit("Target validation or connection failed", 100)
        return {
            "target": original, "hostname": "Not available", "ip": "Not available",
            "status": "Scan could not be completed", "http_status": "N/A",
            "response_time": "N/A", "https": False, "security_headers": {},
            "score": 0, "security_status": str(exc)[:180]
        }
