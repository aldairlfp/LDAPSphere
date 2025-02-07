import select


class LDAPRequestHandler:
    def __init__(self, ldap_url, admin_dn, admin_password):
        self.ldap_url = ldap_url
        self.admin_dn = admin_dn
        self.admin_password = admin_password

    def validate_credentials(self, dn, password, timeout=5):
        """
        Validate user credentials against the LDAP server.

        Args:
            dn (str): User Distinguished Name.
            password (str): User password.
            timeout (int): Maximum waiting time in seconds.

        Returns:
            bool: True if authentication was successful, False otherwise.
        """
        from ldap3 import Server, Connection, ALL

        try:
            # Configurar el servidor LDAP con un timeout
            server = Server(self.ldap_url, get_info=ALL, connect_timeout=timeout)

            # Establecer la conexión con el servidor LDAP
            conn = Connection(server, user=dn, password=password, read_only=True)
            if conn.bind():
                print(f"Successful authentication for {dn}")
                return True
            else:
                print(f"Authentication failure for {dn}: {conn.result}")
                return False
        except Exception as e:
            print(f"Error connecting to the LDAP server: {e}")
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

    def forward_request(self, request):
        from ldap3 import Server, Connection, ALL

        try:
            # Connect to the real LDAP server
            server = Server(self.ldap_url, get_info=ALL)
            conn = Connection(
                server, user=self.admin_dn, password=self.admin_password, auto_bind=True
            )

            conn.socket.send(request)  # Send the request to the real LDAP server

            response_data = b""
            while True:
                # Use select() to wait for readable data with a timeout
                ready, _, _ = select.select([conn.socket], [], [], 2.0)
                if not ready:  # Timeout reached, exit loop
                    break

                chunk = conn.socket.recv(4096)
                if not chunk:  # Connection closed
                    break

                response_data += chunk

                # Stop if we've received a complete LDAP message (handled in handle_client)
                if len(chunk) < 4096:
                    break

            return response_data

        except Exception as e:
            print(f"Error forwarding request: {str(e)}")
            return None
