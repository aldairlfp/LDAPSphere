import asyncio
import os
from pysyncobj import SyncObj, replicated
from dotenv import load_dotenv
from pyasn1.codec.ber import decoder, encoder
from ldap3.protocol.rfc4511 import (
    LDAPMessage,
    BindResponse,
    AddResponse,
    DelResponse,
    SearchResultEntry,
    SearchResultDone,
)

from middleware.request_handler import LDAPRequestHandler
from middleware.utils import get_local_address

load_dotenv()


# Clase para manejar la replicación de operaciones LDAP
class LDAPReplicator(SyncObj):
    def __init__(self, self_address, partner_addresses, on_log_applied_callback=None):
        super().__init__(self_address, partner_addresses)
        self.__logs = []
        self.__on_log_applied_callback = (
            on_log_applied_callback  # Mantén el callback local
        )

    @replicated
    def replicate_operation(self, operation, dn, attributes):
        """Registra y propaga operaciones LDAP."""
        log_entry = {"operation": operation, "dn": dn, "attributes": attributes}
        self.__logs.append(log_entry)
        print(f"Operación replicada: {log_entry}")
        return log_entry

    def apply_logs(self):
        """Aplica todos los logs replicados que aún no han sido procesados."""
        for log_entry in self.__logs:
            if self.__on_log_applied_callback:
                self.__on_log_applied_callback(log_entry)


# Clase para el middleware LDAP Proxy
class LDAPProxyServer:
    def __init__(self, ldap_server, ldap_user, ldap_password, raft_self, raft_partners):
        # Conexión al servidor LDAP
        self.ldap_handler = LDAPRequestHandler(ldap_server, ldap_user, ldap_password)

        # Inicialización del nodo Raft
        self.replicator = LDAPReplicator(raft_self, raft_partners, self.apply_log)

    def apply_log(self, log_entry):
        """Aplica un log replicado al servidor LDAP local."""
        operation = log_entry["operation"]
        dn = log_entry["dn"]
        attributes = log_entry["attributes"]

        if operation == "add":
            print(f"Aplicando operación ADD en {dn}: {attributes}")
            success = self.ldap_handler.add_entry(dn, attributes)
            if not success:
                print(f"Error al aplicar operación ADD en {dn}")
        elif operation == "delete":
            print(f"Aplicando operación DELETE en {dn}")
            result = self.ldap_handler.delete_entry(dn)
            if not result["success"]:
                print(f"Error al aplicar operación DELETE en {dn}")
        else:
            print(f"Operación no soportada: {operation}")

    async def periodic_tasks(self):
        """Ejecuta tareas periódicas como la aplicación de logs."""
        while True:
            if self.replicator._isLeader():
                print("Soy el líder, manejando operaciones locales")
            else:
                print("Soy un seguidor, aplicando logs replicados")
                self.replicator.apply_logs()
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


# Configuración del proxy LDAP y nodos Raft
if __name__ == "__main__":
    # Datos del servidor LDAP
    LDAP_SERVER = os.getenv("LDAP_URL", "ldap://localhost:389")
    LDAP_USER = os.getenv("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=com")
    LDAP_PASSWORD = os.getenv("LDAP_ADMIN_PASSWORD", "1234")

    # Dirección del nodo actual y nodos en la red
    RAFT_SELF = f"{get_local_address()}:{os.getenv('RAFT_PORT', 5000)}"
    RAFT_PARTNERS = [
        node
        for node in os.getenv("RAFT_PARTNERS", "").split(",")
        if node != f"{get_local_address()}:{os.getenv('RAFT_PORT', 5000)}"
    ]
    # Inicializar el servidor proxy
    proxy_server = LDAPProxyServer(
        LDAP_SERVER, LDAP_USER, LDAP_PASSWORD, RAFT_SELF, RAFT_PARTNERS
    )

    # Ejecutar el servidor
    asyncio.run(proxy_server.run("0.0.0.0", os.getenv("PROXY_PORT", 1389)))
