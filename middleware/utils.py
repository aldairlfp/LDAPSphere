import socket


def get_local_address():
    try:
        # Resolver el nombre del host para obtener la dirección local
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except Exception as e:
        print(f"Error obteniendo la dirección local: {e}")
        return "127.0.0.1"  # Dirección predeterminada si falla


def discover_addresses(dns_domain, fallback_ips, timeout=5):
    """
    Resolve addresses via DNS with fallback to a predefined list of IPs.
    """
    try:
        # Attempt to resolve DNS
        srv_records = socket.getaddrinfo(dns_domain, None, family=socket.AF_INET)
        addresses = [rec[4][0] for rec in srv_records]
        print(f"Discovered via DNS: {addresses}")
        return addresses
    except Exception as e:
        print(f"DNS resolution failed for {dns_domain}: {e}")
        print(f"Falling back to predefined IPs: {fallback_ips}")
        return fallback_ips
