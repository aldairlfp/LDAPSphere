from dns import resolver


class DNSAutoDiscovery:
    def __init__(self, dns_name):
        self.dns_name = dns_name

    def get_replica_ips(self):
        try:
            # Resolver direcciones IP con registros A
            answers = resolver.resolve(self.dns_name, "A")
            return [answer.address for answer in answers]
        except Exception as e:
            print(f"Error resolviendo {self.dns_name}: {e}")
            return []

    def get_replica_hosts(self):
        try:
            # Resolver con registros SRV
            srv_records = resolver.resolve(f"_ldap._tcp.{self.dns_name}", "SRV")
            return [
                (str(record.target).rstrip("."), record.port) for record in srv_records
            ]
        except Exception as e:
            print(f"Error resolviendo registros SRV para {self.dns_name}: {e}")
            return []
