import os
import select
import sqlite3
import logging

from middleware.utils import get_local_address


class LDAPRequestHandler:
    def __init__(self, ldap_url, admin_dn, admin_password):
        self.ldap_url = ldap_url
        self.admin_dn = admin_dn
        self.admin_password = admin_password

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
            logging.error(f"Error forwarding request: {str(e)}")
            self.save_failed_request(request)
            return None

    def check_ldap_availability(self):
        """Check if the LDAP server is reachable."""
        from ldap3 import Server, Connection, ALL

        try:
            server = Server(self.ldap_url, get_info=ALL)
            conn = Connection(
                server, user=self.admin_dn, password=self.admin_password, auto_bind=True
            )
            return True  # LDAP server is available
        except Exception:
            return False  # LDAP server is offline

    def save_failed_request(self, request):
        """Save the failed LDAP request to the database for future retries."""
        base = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base, "..", f"failed_requests_{get_local_address()}.db")
        with sqlite3.connect(path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS failed_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, request BLOB)"
            )
            cursor.execute(
                "INSERT INTO failed_requests (request) VALUES (?)", (request,)
            )
            conn.commit()
