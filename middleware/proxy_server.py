import asyncio
from pyasn1.codec.ber import decoder, encoder
from ldap3.protocol.rfc4511 import (
    LDAPMessage,
    BindResponse,
    AddResponse,
    DelResponse,
    ModifyResponse,
    SearchResultEntry,
    SearchResultDone,
)

from middleware.replicator import LDAPReplicator
from middleware.request_handler import LDAPRequestHandler
from middleware.utils import get_local_address


class LDAPProxyServer:
    def __init__(
        self,
        ldap_server,
        ldap_user,
        ldap_password,
        raft_self,
        raft_partners,
        logs_file=f"logs_{get_local_address()}.json",
    ):
        # Conexión al servidor LDAP
        self.ldap_handler = LDAPRequestHandler(ldap_server, ldap_user, ldap_password)
        self.replicator = LDAPReplicator(raft_self, raft_partners, logs_file=logs_file)
        self.last_applied_index = self.load_last_applied_index()

    def load_last_applied_index(self):
        """Carga el último índice de operación aplicada desde un archivo."""
        try:
            with open(f"last_applied_index_{get_local_address()}.txt", "r") as f:
                return int(f.read().strip())
        except FileNotFoundError:
            return 0

    def save_last_applied_index(self):
        """Guarda el índice de la última operación aplicada."""
        with open(f"last_applied_index_{get_local_address()}.txt", "w") as f:
            f.write(str(self.last_applied_index))

    def apply_logs(self):
        """Aplica todos los logs pendientes desde el replicador."""
        logs = self.replicator.get_logs()
        for log_entry in logs:
            if log_entry["log_index"] > self.last_applied_index:
                self.apply_log(log_entry)
                self.last_applied_index = log_entry["log_index"]
                self.save_last_applied_index()

    def apply_log(self, log_entry):
        """Aplica una operación individual al servidor LDAP."""
        operation = log_entry["operation"]
        dn = log_entry["dn"]
        attributes = log_entry["attributes"]

        if operation == "add":
            success = self.ldap_handler.add_entry(dn, attributes)
            if not success:
                print(f"Error al aplicar operación ADD en {dn}.")
        elif operation == "delete":
            result = self.ldap_handler.delete_entry(dn)
            if not result["success"]:
                print(f"Error al aplicar operación DELETE en {dn}.")
        elif operation == "modify":
            result = self.ldap_handler.modify_entry(dn, attributes)
            if not result["success"]:
                print(f"Error al aplicar operación MODIFY en {dn}.")
        else:
            print(f"Operación no soportada: {operation}")

    async def periodic_tasks(self):
        """Ejecuta tareas periódicas como la aplicación de logs."""
        while True:
            print(self.replicator.get_logs())
            # Save the logs
            self.replicator.save_logs()
            if self.replicator._isLeader():
                print("Soy el líder, manejando operaciones locales")
            else:
                print("Soy un seguidor, aplicando logs replicados")
                self.apply_logs()
            await asyncio.sleep(5)

    async def handle_client(self, reader, writer):
        """
        Aquí puedes integrar un servidor para interceptar operaciones
        desde clientes externos, o un mecanismo para manejar solicitudes.
        """
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
                # print(f"Mensaje LDAP decodificado: {ldap_message.prettyPrint()}")

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

                    else:
                        add_response = AddResponse()
                        add_response["resultCode"] = 80  # other
                        add_response["matchedDN"] = ""
                        add_response["diagnosticMessage"] = "Failed to add entry"

                    self.replicator.replicate_operation("add", dn, attributes)

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
                    else:
                        del_response = DelResponse()
                        del_response["resultCode"] = 80  # other
                        del_response["matchedDN"] = ""
                        del_response["diagnosticMessage"] = result["description"]

                    self.replicator.replicate_operation("delete", dn, {})

                    # Enviar respuesta al cliente
                    ldap_response = LDAPMessage()
                    ldap_response["messageID"] = ldap_message["messageID"]
                    ldap_response["protocolOp"]["delResponse"] = del_response
                    writer.write(encoder.encode(ldap_response))
                    await writer.drain()
                    print(f"Respuesta de Delete enviada: {result}")
                elif protocol_op.getName() == "modifyRequest":
                    dn = str(protocol_op["modifyRequest"])
                    print(f"Modify Request recibido: dn={dn}")

                    result = self.ldap_handler.modify_entry(
                        dn, protocol_op["modifyRequest"]
                    )
                    if result["success"]:
                        modify_response = ModifyResponse()
                        modify_response["resultCode"] = 0
                        modify_response["matchedDN"] = dn
                        modify_response["diagnosticMessage"] = result["description"]
                    else:
                        modify_response = ModifyResponse()
                        modify_response["resultCode"] = 80
                        modify_response["matchedDN"] = ""
                        modify_response["diagnosticMessage"] = result["description"]

                    self.replicator.replicate_operation("modify", dn, )
                    ldap_response = LDAPMessage()
                    ldap_response["messageID"] = ldap_message["messageID"]
                    ldap_response["protocolOp"]["modifyResponse"] = modify_response
                    writer.write(encoder.encode(ldap_response))
                    await writer.drain()
                    print(f"Respuesta de Modify enviada: {result}")

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
        asyncio.create_task(self.periodic_tasks())
        async with server:
            await server.serve_forever()
