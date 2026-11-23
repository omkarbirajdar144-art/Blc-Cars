import ipaddress
import socket


COMMON_PORTS = [21, 22, 25, 53, 80, 443, 3306, 8080]


def check_ports(hostname, resolved_ip=None, progress_callback=None):
    results = []
    try:
        ip = resolved_ip or socket.gethostbyname(hostname)
        if not ipaddress.ip_address(ip).is_global:
            return None, ["Port check blocked for non-public IP."]
        for index, port in enumerate(COMMON_PORTS, start=1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.45)
            try:
                state = "OPEN" if sock.connect_ex((ip, port)) == 0 else "CLOSED"
                results.append(f"Port {port}: {state}")
            finally:
                sock.close()
            if progress_callback:
                progress_callback(f"Checking TCP port {port} ({index}/{len(COMMON_PORTS)})", 72 + round(index / len(COMMON_PORTS) * 26))
        return ip, results
    except (OSError, ValueError):
        return None, ["Port check unavailable."]
