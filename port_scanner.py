import socket


def check_ports(target):

    ports = [21, 22, 25, 53, 80, 443, 3306, 8080]

    results = []

    try:
        ip = socket.gethostbyname(target)

        for port in ports:

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)

            result = sock.connect_ex((ip, port))

            if result == 0:
                results.append(f"Port {port}: OPEN")
            else:
                results.append(f"Port {port}: CLOSED")

            sock.close()

        return ip, results

    except socket.gaierror:
        return None, ["Invalid target"]