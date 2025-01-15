import asyncio
from pyasn1.codec.ber import decoder, encoder
from ldap3.protocol.rfc4511 import (
    LDAPMessage,
    BindResponse,
    AddResponse,
    DelResponse,
    SearchResultEntry,
    SearchResultDone,
)

from middleware.request_parser import LDAPRequestParser
from middleware.dns_discovery import DNSAutoDiscovery
from middleware.coordinator import MiddlewareCoordinator


class LDAPMiddleware:
    def __init__(self, coordinator, ldap_handler):
        self.coordinator = coordinator
        self.ldap_handler = ldap_handler
        self.sessions = {}  # Almacenar el estado por dirección IP

    def discover_replicas(self):
        discovery = DNSAutoDiscovery(self.dns_name)
        replicas = discovery.get_replica_ips()  # O get_replica_hosts() para SRV
        print(f"Réplicas descubiertas: {replicas}")
        return replicas

    async def handle_client(self, reader, writer):
        client_address = writer.get_extra_info("peername")
        print(f"Conexión desde: {client_address}")

        try:
            while True:  # Mantener la conexión abierta mientras el cliente esté activo
                # Leer datos en binario
                data = await reader.read(1024)
                if not data:  # Si no hay datos, el cliente cerró la conexión
                    print(f"Cliente {client_address} cerró la conexión.")
                    break

                print(f"Solicitud binaria recibida: {data}")

                # Decodificar el mensaje LDAP
                ldap_message, _ = decoder.decode(data, asn1Spec=LDAPMessage())
                print(f"Mensaje LDAP decodificado: {ldap_message.prettyPrint()}")

                # Identificar la operación
                protocol_op = ldap_message["protocolOp"]
                print(f"Operación LDAP: {protocol_op.getName()}")

                if protocol_op.getName() == "unbindRequest":
                    # Procesar Unbind Request
                    print("Unbind Request recibido: cerrando la conexión.")
                    break  # Salir del bucle para cerrar la conexión
                elif protocol_op.getName() == "bindRequest":
                    # Procesar Bind Request
                    bind_request = protocol_op["bindRequest"]
                    dn = str(bind_request["name"])
                    password = str(bind_request["authentication"]["simple"])

                    print(f"Bind Request recibido: dn={dn}, password={password}")
                    if self.ldap_handler.validate_credentials(dn, password):
                        bind_response = BindResponse()
                        bind_response["resultCode"] = 0  # success
                        bind_response["matchedDN"] = dn
                        bind_response["diagnosticMessage"] = "Bind successful"
                    else:
                        bind_response = BindResponse()
                        bind_response["resultCode"] = 49  # invalidCredentials
                        bind_response["matchedDN"] = ""
                        bind_response["diagnosticMessage"] = "Invalid credentials"

                    # Enviar respuesta al cliente
                    ldap_response = LDAPMessage()
                    ldap_response["messageID"] = ldap_message["messageID"]
                    ldap_response["protocolOp"]["bindResponse"] = bind_response
                    writer.write(encoder.encode(ldap_response))
                    await writer.drain()
                    print("Respuesta de Bind enviada")

                elif protocol_op.getName() == "searchRequest":
                    # Procesar Search Request (Root DSE)
                    print("Search Request recibido")
                    search_result_entry = SearchResultEntry()
                    search_result_entry["objectName"] = ""
                    search_result_entry["attributes"] = [
                        {"type": "supportedLDAPVersion", "vals": ["3"]}
                    ]

                    search_result_done = SearchResultDone()
                    search_result_done["resultCode"] = 0  # success
                    search_result_done["matchedDN"] = ""
                    search_result_done["diagnosticMessage"] = "Search successful"

                    # Enviar resultados de búsqueda
                    ldap_response_entry = LDAPMessage()
                    ldap_response_entry["messageID"] = ldap_message["messageID"]
                    ldap_response_entry["protocolOp"][
                        "searchResEntry"
                    ] = search_result_entry
                    writer.write(encoder.encode(ldap_response_entry))
                    await writer.drain()

                    ldap_response_done = LDAPMessage()
                    ldap_response_done["messageID"] = ldap_message["messageID"]
                    ldap_response_done["protocolOp"][
                        "searchResDone"
                    ] = search_result_done
                    writer.write(encoder.encode(ldap_response_done))
                    await writer.drain()
                    print("Respuesta de Search enviada")

                elif protocol_op.getName() == "addRequest":
                    # Procesar Add Request
                    add_request = protocol_op["addRequest"]
                    dn = str(add_request["entry"])
                    attributes = {
                        str(attr["type"]): [str(value) for value in attr["vals"]]
                        for attr in add_request["attributes"]
                    }

                    print(f"Add Request recibido: dn={dn}, attributes={attributes}")
                    if self.ldap_handler.add_entry(dn, attributes):
                        add_response = AddResponse()
                        add_response["resultCode"] = 0  # success
                        add_response["matchedDN"] = dn
                        add_response["diagnosticMessage"] = "Add successful"

                        print(self.coordinator.is_leader)
                        # Replicar la operación a las réplicas
                        if self.coordinator.is_leader:
                            print("Replicando operación ADD a las réplicas")
                            self.coordinator.replicate_operation(
                                "add", {"dn": dn, "attributes": attributes}
                            )

                    else:
                        add_response = AddResponse()
                        add_response["resultCode"] = 80  # other
                        add_response["matchedDN"] = ""
                        add_response["diagnosticMessage"] = "Failed to add entry"

                    # Enviar respuesta al cliente
                    ldap_response = LDAPMessage()
                    ldap_response["messageID"] = ldap_message["messageID"]
                    ldap_response["protocolOp"]["addResponse"] = add_response
                    writer.write(encoder.encode(ldap_response))
                    await writer.drain()
                    print("Respuesta de Add enviada")

                elif protocol_op.getName() == "delRequest":
                    # Procesar Delete Request
                    dn = str(protocol_op["delRequest"])
                    print(f"Delete Request recibido: dn={dn}")

                    result = self.ldap_handler.delete_entry(dn)
                    if result["success"]:
                        del_response = DelResponse()
                        del_response["resultCode"] = 0  # success
                        del_response["matchedDN"] = dn
                        del_response["diagnosticMessage"] = result["description"]

                        # Replicar la operación a las réplicas
                        if self.coordinator.is_leader:
                            self.coordinator.replicate_operation("delete", {"dn": dn})

                    else:
                        del_response = DelResponse()
                        del_response["resultCode"] = 80  # other
                        del_response["matchedDN"] = ""
                        del_response["diagnosticMessage"] = result["description"]

                    # Enviar respuesta al cliente
                    ldap_response = LDAPMessage()
                    ldap_response["messageID"] = ldap_message["messageID"]
                    ldap_response["protocolOp"]["delResponse"] = del_response
                    writer.write(encoder.encode(ldap_response))
                    await writer.drain()
                    print(f"Respuesta de Delete enviada: {result}")

                else:
                    raise ValueError(
                        f"Operación LDAP no soportada: {protocol_op.getName()}"
                    )

        except Exception as e:
            print(f"Error: {str(e)}")

        finally:
            # Solo cerrar la conexión si el cliente ya no está activo
            writer.close()
            await writer.wait_closed()
            print("Conexión cerrada correctamente")

    async def run(self, host="127.0.0.1", port=1389):
        server = await asyncio.start_server(self.handle_client, host, port)
        print(f"LDAP Middleware running on {host}:{port}")
        async with server:
            await server.serve_forever()
