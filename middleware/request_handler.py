class LDAPRequestHandler:
    def __init__(self, ldap_url, admin_dn, admin_password):
        self.ldap_url = ldap_url
        self.admin_dn = admin_dn
        self.admin_password = admin_password

    def validate_credentials(self, dn, password):
        from ldap3 import Server, Connection, ALL

        server = Server(self.ldap_url, get_info=ALL)
        conn = Connection(server, user=dn, password=password)
        return conn.bind()

    def add_entry(self, dn, attributes):
        from ldap3 import Server, Connection, ALL

        server = Server(self.ldap_url, get_info=ALL)
        conn = Connection(
            server, user=self.admin_dn, password=self.admin_password, auto_bind=True
        )
        return conn.add(dn, attributes=attributes)
