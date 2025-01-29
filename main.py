import asyncio
import os
from dotenv import load_dotenv

from middleware.proxy_server import LDAPProxyServer
from middleware.utils import get_local_address


load_dotenv()


# Configuración del proxy LDAP y nodos Raft
if __name__ == "__main__":
    # Datos del servidor LDAP
    LDAP_SERVER = os.getenv("LDAP_URL", "ldap://localhost:389")
    LDAP_USER = os.getenv("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=com")
    LDAP_PASSWORD = os.getenv("LDAP_ADMIN_PASSWORD", "1234")
    DNS_DOMAIN = os.getenv("DNS_DOMAIN", "example.com")
    FALLBACK_IPS = os.getenv("FALLBACK_IPS", "").split(",")

    # Dirección del nodo actual y nodos en la red
    RAFT_SELF = f"{get_local_address()}"
    # Inicializar el servidor proxy
    proxy_server = LDAPProxyServer(
        LDAP_SERVER,
        LDAP_USER,
        LDAP_PASSWORD,
        RAFT_SELF,
        DNS_DOMAIN,
        FALLBACK_IPS,
        os.getenv("RAFT_PORT", 5000),
    )

    # Ejecutar el servidor
    asyncio.run(proxy_server.run("0.0.0.0", os.getenv("PROXY_PORT", 1389)))
