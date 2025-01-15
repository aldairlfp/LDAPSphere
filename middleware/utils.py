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
