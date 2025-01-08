from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException
import asyncio

class DistributedLDAPMiddleware:
    def __init__(self, servers):
        self.servers = servers
        self.current_server = 0

    def get_next_server(self):
        server = self.servers[self.current_server]
        self.current_server = (self.current_server + 1) % len(self.servers)
        return server

    async def replicate_change(self, dn, changes):
        for server_url in self.servers:
            try:
                server = Server(server_url, get_info=ALL)
                conn = Connection(server)
                if conn.bind():
                    conn.modify(dn, changes)
                    conn.unbind()
                else:
                    print(f"Replication failed on {server_url}")
            except LDAPException as e:
                print(f"Error replicating to {server_url}: {e}")

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info("peername")
        print(f"Connection from {addr}")

        try:
            data = await reader.read(1024)
            operation, dn, attribute, value = data.decode().split(";")

            backend_server = self.get_next_server()
            server = Server(backend_server, get_info=ALL)
            conn = Connection(server)

            if not conn.bind():
                raise LDAPException(f"Failed to bind to {backend_server}")

            if operation == "update":
                conn.modify(dn, {attribute: [(MODIFY_REPLACE, [value])]})
                if conn.result['description'] == "success":
                    await self.replicate_change(dn, {attribute: [(MODIFY_REPLACE, [value])]})
                    writer.write(b"Update successful and replicated")
                else:
                    writer.write(f"Error: {conn.result}".encode())
            conn.unbind()

        except Exception as e:
            print(f"Error: {e}")
            writer.write(f"Error: {e}".encode())

        finally:
            writer.close()
            await writer.wait_closed()

    async def run_server(self, host="127.0.0.1", port=1389):
        server = await asyncio.start_server(self.handle_client, host, port)
        print(f"Distributed LDAP Middleware running on {host}:{port}")
        async with server:
            await server.serve_forever()


# Servers
LDAP_SERVERS = ["ldap://127.0.0.1", "ldap://192.168.1.10"]
middleware = DistributedLDAPMiddleware(LDAP_SERVERS)
asyncio.run(middleware.run_server())
