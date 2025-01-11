from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
from middleware.request_validator import LDAPRequestValidator  # Importar el validador


class LDAPRequestHandler:
    def __init__(self, ldap_url, admin_dn, admin_password):
        self.server = Server(ldap_url, get_info=ALL)
        self.admin_dn = admin_dn
        self.admin_password = admin_password

    def handle_request(self, request):
        # Validar la solicitud antes de procesarla
        LDAPRequestValidator.validate_request(request)

        # Conexión al servidor LDAP
        with Connection(
            self.server,
            user=self.admin_dn,
            password=self.admin_password,
            auto_bind=True,
        ) as conn:
            operation = request["operation"]
            dn = request["dn"]
            attributes = request.get("attributes")

            if operation == "add":
                conn.add(dn, attributes=attributes)
                return conn.result

            elif operation == "modify":
                changes = {
                    attr: [(MODIFY_REPLACE, values)]
                    for attr, values in attributes.items()
                }
                conn.modify(dn, changes)
                return conn.result

            elif operation == "delete":
                conn.delete(dn)
                return conn.result

            elif operation == "search":
                search_filter = request.get("filter", "(objectClass=*)")
                conn.search(dn, search_filter, attributes=attributes)
                return conn.entries

            else:
                raise ValueError(f"Operación no soportada: {operation}")
