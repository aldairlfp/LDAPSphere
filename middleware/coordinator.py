import requests
from middleware.dns_discovery import DNSAutoDiscovery


class MiddlewareCoordinator:
    def __init__(self, dns_name):
        self.dns_name = dns_name
        self.replicas = self.discover_replicas()

    def discover_replicas(self):
        discovery = DNSAutoDiscovery(self.dns_name)
        replicas = discovery.get_replica_ips()
        print(f"Réplicas descubiertas: {replicas}")
        return replicas

    def send_operation(self, operation, dn, attributes=None):
        payload = {"operation": operation, "dn": dn, "attributes": attributes}
        for replica in self.replicas:
            try:
                print(f"Enviando operación a {replica}: {payload}")
                response = requests.post(
                    f"http://{replica}:5000/replicate", json=payload
                )
                if response.status_code != 200:
                    print(f"Error replicando en {replica}: {response.text}")
            except Exception as e:
                print(f"Error conectando con {replica}: {e}")
