import socket

from urllib.parse import urlparse


def check_ports(target):

    ports = [
        21,    # FTP
        22,    # SSH
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        443,   # HTTPS
        3306,  # MySQL
        8080   # HTTP Proxy
    ]

    results = []

    try:

        # Add protocol if missing
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        # Extract hostname
        parsed = urlparse(target)
        hostname = parsed.hostname

        if not hostname:
            return None, ["Invalid target"]

        # Resolve hostname
        ip = socket.gethostbyname(hostname)

        for port in ports:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(0.7)

            result = sock.connect_ex(
                (ip, port)
            )

            if result == 0:
                results.append(
                    f"Port {port}: OPEN"
                )
            else:
                results.append(
                    f"Port {port}: CLOSED"
                )

            sock.close()

        return ip, results

    except socket.gaierror:
        return None, ["DNS resolution failed"]

    except Exception as e:
        return None, [f"Scan error: {str(e)}"]