import asyncio
import os
import logging
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

    # Dirección del nodo actual y nodos en la red
    RAFT_SELF = f"{get_local_address()}"
    FALLBACK_IPS = os.getenv("FALLBACK_IPS")
    # Inicializar el servidor proxy
    cluster_ip = os.getenv("CLUSTER_IP")

    if FALLBACK_IPS:
        cluster = FALLBACK_IPS.split(",")
    else:
        cluster = []

    proxy_server = LDAPProxyServer(
        LDAP_SERVER,
        LDAP_USER,
        LDAP_PASSWORD,
        RAFT_SELF,
        cluster,
        cluster_ip,
        os.getenv("RAFT_PORT", 5000),
    )

    # Ejecutar el servidor
    logging.info("Starting LDAP Proxy Server...")
    asyncio.run(proxy_server.run("0.0.0.0", os.getenv("PROXY_PORT", 1390)))
