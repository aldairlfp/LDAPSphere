import asyncio
import json
import os
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
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

from middleware.replicator import LDAPReplicator
from middleware.request_handler import LDAPRequestHandler
from middleware.utils import discover_addresses, get_local_address

LDAP_OPERATIONS = {0: MODIFY_ADD, 1: MODIFY_DELETE, 2: MODIFY_REPLACE}


class LDAPProxyServer:
    def __init__(
        self,
        ldap_server,
        ldap_user,
        ldap_password,
        raft_self,
        dns_domain,
        fallback_ips,
        port=5000,
        logs_file=f"logs_{get_local_address()}.json",
    ):
        # Resolve partners dynamically
        self.raft_partners = discover_addresses(dns_domain, fallback_ips)
        self.raft_partners = [addr for addr in self.raft_partners if addr != raft_self]
        self.raft_partners = [f"{addr}:{port}" for addr in self.raft_partners]

        # Existing logic remains unchanged
        self.ldap_handler = LDAPRequestHandler(ldap_server, ldap_user, ldap_password)
        self.replicator = LDAPReplicator(
            f"{raft_self}:{port}", self.raft_partners, logs_file=logs_file
        )

        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.last_applied_index_file = os.path.join(
            base_dir, "..", f"last_applied_index_{get_local_address()}.txt"
        )
        self.local_logs_file = os.path.join(
            base_dir, "..", f"local_logs_{get_local_address()}.json"
        )

        self.last_applied_index = self.load_last_applied_index()
        self.local_logs = self.load_local_logs()

    def load_last_applied_index(self):
        """Loads the last applied operation index from a file."""
        try:
            with open(self.last_applied_index_file, "r") as f:
                return int(f.read().strip())
        except FileNotFoundError:
            return 0

    def save_last_applied_index(self):
        """Saves the index of the last operation applied."""
        with open(self.last_applied_index_file, "w") as f:
            f.write(str(self.last_applied_index))

    def load_local_logs(self):
        """Load local logs from a file."""
        try:
            with open(self.local_logs_file, "r") as f:
                return json.loads(f.read())
        except FileNotFoundError:
            return []

    def save_local_logs(self):
        """Save local logs to a file."""
        with open(self.local_logs_file, "w") as f:
            json.dump(self.local_logs, f)

    def apply_logs(self):
        """Applies all pending logs from the replicator."""
        logs = self.replicator.get_logs()
        for log_entry in logs:
            if log_entry["log_index"] > self.last_applied_index:
                self.apply_log(log_entry)
                self.last_applied_index = log_entry["log_index"]
                self.save_last_applied_index()

    def apply_log(self, log_entry):
        """Applies a single operation to the LDAP server."""
        if (
            log_entry["local_execution"]
            and log_entry["source_ip"] == get_local_address()
        ):
            return

        operation = log_entry["operation"]
        dn = log_entry["dn"]
        attributes = log_entry["attributes"]

        if operation == "add":
            success = self.ldap_handler.add_entry(dn, attributes)
            if not success:
                print(f"Error when applying ADD operation on {dn}.")
        elif operation == "delete":
            result = self.ldap_handler.delete_entry(dn)
            if not result["success"]:
                print(f"Error when applying DELETE operation on {dn}.")
        elif operation == "modify":
            result = self.ldap_handler.modify_entry(dn, attributes)
            if not result["success"]:
                print(f"Error when applying MODIFY operation on {dn}.")
        else:
            print(f"Unsupported operation: {operation}")

    def replicate_operation(self, operation, dn, attributes):
        """Logs and propagates LDAP operations with a log index."""
        if self.replicator.isReady():
            log_entry = self.replicator.replicate_operation(
                operation, dn, attributes, get_local_address()
            )
            # print(f"Log entry -> {log_entry}")
        else:
            self.local_logs.append(
                {
                    "operation": operation,
                    "dn": dn,
                    "attributes": attributes,
                    "source_ip": get_local_address(),
                    "local_execution": True,
                }
            )
            self.save_local_logs()

    def replicate_local_logs(self):
        """Replicates pending local operations."""
        for log_entry in self.local_logs:
            operation = log_entry["operation"]
            dn = log_entry["dn"]
            attributes = log_entry["attributes"]
            source_ip = log_entry["source_ip"]
            local_execution = log_entry["local_execution"]
            self.replicator.replicate_operation(
                operation, dn, attributes, source_ip, local_execution
            )
        self.local_logs = []
        self.save_local_logs()

    async def periodic_tasks(self):
        """Execute periodic tasks such as applying logs."""
        while True:
            # print(self.replicator.get_logs())
            # Save the logs
            if self.replicator.isReady():
                self.replicate_local_logs()
            self.replicator.save_logs()
            if self.replicator._isLeader():
                print("I am the leader, managing local operations")
            else:
                print("I am a follower, applying replicated logs")
            self.apply_logs()
            await asyncio.sleep(5)

    async def handle_client(self, reader, writer):
        """
        Here you can integrate a server to intercept operations
        from external clients, or a mechanism to handle requests.
        """
        client_address = writer.get_extra_info("peername")
        print(f"Connection from: {client_address}")

        try:
            while True:  # Keep the connection open while the client is active
                # Read binary data
                data = await reader.read(1024)
                if not data:  # If no data, the client closed the connection
                    print(f"Client {client_address} closed the connection.")
                    break

                # print(f"Binary request received: {data}")

                # Decode the LDAP message
                ldap_message, _ = decoder.decode(data, asn1Spec=LDAPMessage())
                # print(f"Decoded LDAP message: {ldap_message.prettyPrint()}")

                # Identify the operation
                protocol_op = ldap_message["protocolOp"]
                print(f"LDAP operation: {protocol_op.getName()}")

                if protocol_op.getName() == "unbindRequest":
                    # Process Unbind Request
                    print("Unbind Request received: closing the connection.")
                    break  # Exit the loop to close the connection
                elif protocol_op.getName() == "bindRequest":
                    # Process Bind Request
                    bind_request = protocol_op["bindRequest"]
                    dn = str(bind_request["name"])
                    password = str(bind_request["authentication"]["simple"])

                    print(f"Bind Request received: dn={dn}, password={password}")
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

                    # Send response to the client
                    ldap_response = LDAPMessage()
                    ldap_response["messageID"] = ldap_message["messageID"]
                    ldap_response["protocolOp"]["bindResponse"] = bind_response
                    writer.write(encoder.encode(ldap_response))
                    await writer.drain()
                    print("Bind response sent")

                elif protocol_op.getName() == "searchRequest":
                    # Process Search Request (Root DSE)
                    print("Search Request received")
                    search_result_entry = SearchResultEntry()
                    search_result_entry["objectName"] = ""
                    search_result_entry["attributes"] = [
                        {"type": "supportedLDAPVersion", "vals": ["3"]}
                    ]

                    search_result_done = SearchResultDone()
                    search_result_done["resultCode"] = 0  # success
                    search_result_done["matchedDN"] = ""
                    search_result_done["diagnosticMessage"] = "Search successful"

                    # Send search results
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
                    print("Search response sent")

                elif protocol_op.getName() == "addRequest":
                    # Process Add Request
                    add_request = protocol_op["addRequest"]
                    dn = str(add_request["entry"])
                    attributes = {
                        str(attr["type"]): [str(value) for value in attr["vals"]]
                        for attr in add_request["attributes"]
                    }

                    print(f"Add Request received: dn={dn}, attributes={attributes}")
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

                    self.replicate_operation("add", dn, attributes)

                    # Send response to the client
                    ldap_response = LDAPMessage()
                    ldap_response["messageID"] = ldap_message["messageID"]
                    ldap_response["protocolOp"]["addResponse"] = add_response
                    writer.write(encoder.encode(ldap_response))
                    await writer.drain()
                    print("Add response sent")

                elif protocol_op.getName() == "delRequest":
                    # Process Delete Request
                    dn = str(protocol_op["delRequest"])
                    print(f"Delete Request received: dn={dn}")

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

                    self.replicate_operation("delete", dn, {})

                    # Send response to the client
                    ldap_response = LDAPMessage()
                    ldap_response["messageID"] = ldap_message["messageID"]
                    ldap_response["protocolOp"]["delResponse"] = del_response
                    writer.write(encoder.encode(ldap_response))
                    await writer.drain()
                    print(f"Delete response sent: {result}")
                elif protocol_op.getName() == "modifyRequest":
                    # Extract the DN of the object to be modified
                    dn = str(
                        protocol_op["modifyRequest"]["object"]
                    )  # Convert to string
                    print(f"Modify Request received: dn={dn}")

                    # Process the changes
                    changes = []
                    for change in protocol_op["modifyRequest"]["changes"]:
                        operation = LDAP_OPERATIONS[
                            change["operation"]
                        ]  # Map operation
                        attribute = str(
                            change["modification"]["type"]
                        )  # Convert to string
                        values = [
                            str(value) for value in change["modification"]["vals"]
                        ]  # Convert to list of strings
                        changes.append(
                            {
                                "operation": operation,
                                "attribute": attribute,
                                "values": values,
                            }
                        )

                    # Restructure changes for the modify_entry method
                    ldap_changes = {}
                    for change in changes:
                        ldap_changes.setdefault(change["attribute"], []).append(
                            (change["operation"], change["values"])
                        )

                    # Apply the operation to the LDAP server
                    result = self.ldap_handler.modify_entry(dn, ldap_changes)
                    if result["success"]:
                        modify_response = ModifyResponse()
                        modify_response["resultCode"] = 0
                        modify_response["matchedDN"] = dn
                        modify_response["diagnosticMessage"] = result["description"]
                    else:
                        modify_response = ModifyResponse()
                        modify_response["resultCode"] = 80  # Generic error code
                        modify_response["matchedDN"] = ""
                        modify_response["diagnosticMessage"] = result["description"]

                    # Replicate the operation
                    self.replicate_operation(
                        "modify", dn, ldap_changes
                    )  # Here the changes are already serializable

                    # Send response to the client
                    ldap_response = LDAPMessage()
                    ldap_response["messageID"] = ldap_message["messageID"]
                    ldap_response["protocolOp"]["modifyResponse"] = modify_response
                    writer.write(encoder.encode(ldap_response))
                    await writer.drain()
                    print(f"Modify response sent: {result}")

                else:
                    raise ValueError(
                        f"Unsupported LDAP operation: {protocol_op.getName()}"
                    )

        except Exception as e:
            print(f"Error: {str(e)}")

        finally:
            # Only close the connection if the client is no longer active
            writer.close()
            await writer.wait_closed()
            print("Connection closed properly")

    async def run(self, host="127.0.0.1", port=1389):
        server = await asyncio.start_server(self.handle_client, host, port)
        print(f"LDAP Middleware running on {host}:{port}")
        asyncio.create_task(self.periodic_tasks())
        async with server:
            await server.serve_forever()
