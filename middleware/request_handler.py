class LDAPRequestHandler:
    def __init__(self, ldap_url, admin_dn, admin_password):
        self.ldap_url = ldap_url
        self.admin_dn = admin_dn
        self.admin_password = admin_password

    def validate_credentials(self, dn, password, timeout=5):
        """
        Valida las credenciales del usuario contra el servidor LDAP.

        Args:
            dn (str): Distinguished Name del usuario.
            password (str): Contraseña del usuario.
            timeout (int): Tiempo máximo de espera en segundos.

        Returns:
            bool: True si la autenticación fue exitosa, False en caso contrario.
        """
        from ldap3 import Server, Connection, ALL

        try:
            # Configurar el servidor LDAP con un timeout
            server = Server(self.ldap_url, get_info=ALL, connect_timeout=timeout)

            # Establecer la conexión con el servidor LDAP
            conn = Connection(server, user=dn, password=password, read_only=True)
            if conn.bind():
                print(f"Autenticación exitosa para {dn}")
                return True
            else:
                print(f"Fallo de autenticación para {dn}: {conn.result}")
                return False
        except Exception as e:
            print(f"Error conectando con el servidor LDAP: {e}")
            return False

    def add_entry(self, dn, attributes):
        from ldap3 import Server, Connection, ALL

        server = Server(self.ldap_url, get_info=ALL)
        conn = Connection(
            server, user=self.admin_dn, password=self.admin_password, auto_bind=True
        )
        return conn.add(dn, attributes=attributes)

    def delete_entry(self, dn):
        from ldap3 import Server, Connection, ALL

        try:
            # Conectar al servidor LDAP real
            server = Server(self.ldap_url, get_info=ALL)
            conn = Connection(
                server, user=self.admin_dn, password=self.admin_password, auto_bind=True
            )

            # Ejecutar la operación de eliminación
            if conn.delete(dn):
                return {"success": True, "description": "Entry deleted successfully"}
            else:
                # Capturar el error del servidor LDAP real
                return {
                    "success": False,
                    "description": conn.result["description"],
                    "details": conn.result,
                }
        except Exception as e:
            # Manejar errores de conexión u otros errores inesperados
            return {"success": False, "description": str(e)}

    def modify_entry(self, dn, changes):
        from ldap3 import Server, Connection, ALL, MODIFY_REPLACE

        try:
            # Conectar al servidor LDAP real
            server = Server(self.ldap_url, get_info=ALL)
            conn = Connection(
                server, user=self.admin_dn, password=self.admin_password, auto_bind=True
            )

            # Ejecutar la operación de modificación
            if conn.modify(dn, changes):
                return {"success": True, "description": "Entry modified successfully"}
            else:
                # Capturar el error del servidor LDAP real
                return {
                    "success": False,
                    "description": conn.result["description"],
                    "details": conn.result,
                }
        except Exception as e:
            # Manejar errores de conexión u otros errores inesperados
            return {"success": False, "description": str(e)}
