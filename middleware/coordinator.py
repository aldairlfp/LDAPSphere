import requests
from middleware.dns_discovery import DNSAutoDiscovery
from middleware.utils import get_local_address


class MiddlewareCoordinator:
    def __init__(self, dns_name):
        self.dns_name = dns_name
        self.my_address = get_local_address()
        self.is_leader = False
        self.replicas = []
        self.initialize_role()

    def initialize_role(self):
        # Obtener las IPs de la red usando DNS
        discovery = DNSAutoDiscovery(self.dns_name)
        replicas = discovery.get_replica_ips()
        print(f"Réplicas descubiertas: {replicas}")

        # Ordenar las IPs y determinar el liderazgo
        sorted_replicas = sorted(replicas)
        self.replicas = sorted_replicas

        # La primera IP en la lista se considera como posible líder
        potential_leader = sorted_replicas[0]
        print(f"Evaluando liderazgo con {potential_leader} como líder potencial.")

        if potential_leader == self.my_address:
            # Soy la primera IP, por lo tanto, soy el líder
            self.is_leader = True
            print(f"Este middleware es el líder: {self.my_address}")
        else:
            # Verificar si el supuesto líder está en línea y es válido
            try:
                response = requests.get(
                    f"http://{potential_leader}:5000/health", timeout=5
                )
                if (
                    response.status_code == 200
                    and response.json().get("role") == "leader"
                ):
                    print(f"Líder confirmado en {potential_leader}. Registrándose...")
                    self.register_with_leader(potential_leader)
                else:
                    print(
                        f"Líder en {potential_leader} no válido. Asumiendo liderazgo."
                    )
                    self.is_leader = True
            except Exception as e:
                print(
                    f"No se pudo conectar con {potential_leader}: {e}. Asumiendo liderazgo."
                )
                self.is_leader = True

    def register_with_leader(self, leader_address):
        try:
            response = requests.post(
                f"http://{leader_address}:5000/register_replica",
                json={"replica_address": self.my_address},
            )
            if response.status_code == 200:
                print(f"Registrado con éxito en el líder {leader_address}")
            else:
                print(f"Error al registrarse con el líder: {response.text}")
        except Exception as e:
            print(f"Error conectando con el líder {leader_address}: {e}")

    def add_replica(self, replica_address):
        if replica_address not in self.replicas:
            self.replicas.append(replica_address)
            print(f"Réplica añadida: {replica_address}")

    def get_replicas(self):
        return self.replicas

    def replicate_operation(self, operation, data):
        """
        Replica una operación (add/delete) a todas las réplicas registradas.
        Args:
            operation (str): Tipo de operación ('add' o 'delete').
            data (dict): Datos de la operación.
        """
        print(self.replicas)
        for replica in self.replicas:
            try:
                response = requests.post(
                    f"http://{replica}:5000/replicate",
                    json={"operation": operation, "data": data},
                )
                if response.status_code == 200:
                    print(f"Operación {operation} replicada exitosamente en {replica}")
                else:
                    print(
                        f"Error replicando operación {operation} en {replica}: {response.text}"
                    )
            except Exception as e:
                print(f"Error conectando con la réplica {replica}: {e}")
