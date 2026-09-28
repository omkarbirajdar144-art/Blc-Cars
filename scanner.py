
import socket
import requests
from urllib.parse import urlparse
import time


def scan_target(target):

    try:
        # URL मध्ये https नसेल तर add करा
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        parsed = urlparse(target)
        hostname = parsed.hostname

        if not hostname:
            raise ValueError("Invalid URL")

        # IP Address
        ip = socket.gethostbyname(hostname)

        # Website request
        start_time = time.time()

        response = requests.get(
            target,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "CyberGuard-Security-Scanner/1.0"
            }
        )

        response_time = round(
            (time.time() - start_time) * 1000,
            2
        )

        # HTTPS
        https = response.url.startswith("https://")

        # Security headers
        headers = response.headers

        security_headers = {
            "Content-Security-Policy":
                "Content-Security-Policy" in headers,

            "X-Content-Type-Options":
                "X-Content-Type-Options" in headers,

            "X-Frame-Options":
                "X-Frame-Options" in headers,

            "Strict-Transport-Security":
                "Strict-Transport-Security" in headers
        }

        # Security score
        score = 0

        if https:
            score += 40

        if response.status_code == 200:
            score += 20

        if security_headers["Content-Security-Policy"]:
            score += 10

        if security_headers["X-Content-Type-Options"]:
            score += 10

        if security_headers["X-Frame-Options"]:
            score += 10

        if security_headers["Strict-Transport-Security"]:
            score += 10

        # Status
        if score >= 80:
            security_status = "Good Security Posture"
        elif score >= 50:
            security_status = "Needs Improvement"
        else:
            security_status = "Security Warnings Found"

        return {
            "target": target,
            "hostname": hostname,
            "ip": ip,
            "status": "Website reachable",
            "http_status": response.status_code,
            "response_time": response_time,
            "https": https,
            "security_headers": security_headers,
            "score": score,
            "security_status": security_status
        }

    except requests.RequestException as e:

        return {
            "target": target,
            "hostname": "Not Found",
            "ip": "Not Found",
            "status": "Website unreachable",
            "http_status": "N/A",
            "response_time": "N/A",
            "https": False,
            "security_headers": {},
            "score": 0,
            "security_status": "Unable to scan"
        }

    except Exception as e:

        return {
            "target": target,
            "hostname": "Not Found",
            "ip": "Not Found",
            "status": "Invalid URL or Domain",
            "http_status": "N/A",
            "response_time": "N/A",
            "https": False,
            "security_headers": {},
            "score": 0,
            "security_status": "Invalid target"
        }

