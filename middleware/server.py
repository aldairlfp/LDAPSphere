import asyncio

from middleware.request_parser import LDAPRequestParser


class LDAPMiddleware:
    def __init__(self, host, port, ldap_handler):
        self.host = host
        self.port = port
        self.ldap_handler = ldap_handler

    async def handle_client(self, reader, writer):
        try:
            # Leer datos del cliente
            data = await reader.read(1024)
            command = data.decode()

            # Parsear el comando LDAP
            request = LDAPRequestParser.parse_command(command)

            # Procesar el request (esto incluye validación ahora)
            result = self.ldap_handler.handle_request(request)

            # Enviar respuesta
            response = {"status": "success", "result": result}
            writer.write(str(response).encode())
            await writer.drain()

        except ValueError as e:
            # Manejar errores de validación
            error_response = {"status": "error", "message": str(e)}
            writer.write(str(error_response).encode())
            await writer.drain()

        except Exception as e:
            # Manejar otros errores
            error_response = {
                "status": "error",
                "message": "Error interno del servidor",
            }
            writer.write(str(error_response).encode())
            await writer.drain()

        finally:
            writer.close()
            await writer.wait_closed()

    async def run(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        print(f"LDAP Middleware running on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()
