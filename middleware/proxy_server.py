import asyncio
import json
import os
import time
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

from metrics.measure_ldap_direct import measure_direct_ldap_query
from middleware.replicator import LDAPReplicator
from middleware.request_handler import LDAPRequestHandler
from middleware.utils import discover_addresses, get_local_address

from logger import logger as logging

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
        self.raft_partners = [
            f"{addr}:{port}" for addr in self.raft_partners if addr != f"{raft_self}"
        ]

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
        # self.replicator.replicate_operation(
        #     operation, dn, attributes, get_local_address()
        # )

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
            # if self.replicator._isLeader():
            #     print("I am the leader, managing local operations")
            # else:
            #     print("I am a follower, applying replicated logs")
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
                start_time = time.perf_counter()

                # Read binary data
                try:
                    # Read LDAP request (with a timeout to prevent hangs)
                    data = await asyncio.wait_for(reader.read(1024), timeout=5.0)

                    if not data:  # Client closed connection
                        print(f"Client {client_address} closed the connection.")
                        break

                    # Decode the LDAP message
                    try:
                        ldap_message, _ = decoder.decode(data, asn1Spec=LDAPMessage())
                    except Exception as decode_error:
                        print(f"⚠️ Decode Error: {decode_error} - Data: {data}")
                        continue  # Skip this iteration if decoding fails

                    # Decode the LDAP message
                    ldap_message, _ = decoder.decode(data, asn1Spec=LDAPMessage())

                    # Identify the operation
                    protocol_op = ldap_message["protocolOp"]
                    print(f"LDAP operation: {protocol_op.getName()}")

                    if protocol_op.getName() == "unbindRequest":
                        await self.handle_unbind_request(writer)
                        break  # Exit the loop to close the connection
                    elif protocol_op.getName() == "bindRequest":
                        await self.handle_bind_request(
                            ldap_message, protocol_op, writer
                        )
                    elif protocol_op.getName() == "addRequest":
                        await self.handle_add_request(ldap_message, protocol_op, writer)
                    elif protocol_op.getName() == "delRequest":
                        await self.handle_delete_request(
                            ldap_message, protocol_op, writer
                        )
                    elif protocol_op.getName() == "modifyRequest":
                        await self.handle_modify_request(
                            ldap_message, protocol_op, writer
                        )
                    else:
                        raw_response = self.ldap_handler.forward_request(data)

                        if raw_response:
                            while raw_response:
                                try:
                                    # Decode and process one LDAP message at a time
                                    ldap_response, rest = decoder.decode(
                                        raw_response, asn1Spec=LDAPMessage()
                                    )
                                    print("aaaa1")

                                    # Encode properly before sending back
                                    encoded_response = encoder.encode(ldap_response)
                                    writer.write(encoded_response)
                                    await writer.drain()
                                    print("aaaa2")

                                    # If it's the final response message (e.g., searchResDone), stop
                                    if (
                                        ldap_response["protocolOp"].getName()
                                        == "searchResDone"
                                    ):
                                        break

                                    print("aaaa3")

                                    raw_response = (
                                        rest  # Process remaining response data
                                    )
                                except:
                                    break  # Break on decoding failure (unlikely)
                except TimeoutError as e:
                    print(
                        f"⚠️ Timeout: No data received from {client_address} in 5 seconds."
                    )
                    continue  # Retry reading instead of closing the connection

        except Exception as e:
            print(f"Error: {str(e)}")

        finally:
            writer.close()
            await writer.wait_closed()
            print("Connection closed properly")

            end_time = time.perf_counter()
            latency = end_time - start_time

    async def handle_unbind_request(self, writer):
        """Handles an LDAP unbind request by properly closing the connection."""
        print("Unbind Request received: closing the connection.")

        try:
            writer.close()  # Close the connection properly
            await writer.wait_closed()  # Ensure it's fully closed
            print("Connection closed successfully.")
        except Exception as e:
            print(f"Error closing connection: {str(e)}")

    async def handle_bind_request(self, ldap_message, protocol_op, writer):
        """Handles an LDAP bind request and sends an appropriate response."""
        bind_request = protocol_op["bindRequest"]
        dn = str(bind_request["name"])
        password = str(bind_request["authentication"]["simple"])

        print(
            f"Bind Request received: dn={dn}, password=******"
        )  # Hide password in logs

        try:
            # Validate credentials
            is_valid = self.ldap_handler.validate_credentials(dn, password)
            bind_response = BindResponse()

            if is_valid:
                bind_response["resultCode"] = 0  # Success
                bind_response["matchedDN"] = dn
                bind_response["diagnosticMessage"] = "Bind successful"
                print("✅ Successful bind")
            else:
                bind_response["resultCode"] = 49  # Invalid Credentials
                bind_response["matchedDN"] = ""
                bind_response["diagnosticMessage"] = "Invalid credentials"
                print("❌ Invalid credentials")

            # Encode and send the response
            ldap_response = LDAPMessage()
            ldap_response["messageID"] = ldap_message["messageID"]
            ldap_response["protocolOp"]["bindResponse"] = bind_response

            writer.write(encoder.encode(ldap_response))
            await writer.drain()
            print("Bind response sent.")

        except Exception as e:
            print(f"⚠️ Error in handle_bind_request: {str(e)}")

    async def handle_search_request(self, ldap_message, writer):
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

        ldap_response_entry = LDAPMessage()
        ldap_response_entry["messageID"] = ldap_message["messageID"]
        ldap_response_entry["protocolOp"]["searchResEntry"] = search_result_entry
        writer.write(encoder.encode(ldap_response_entry))
        await writer.drain()

        ldap_response_done = LDAPMessage()
        ldap_response_done["messageID"] = ldap_message["messageID"]
        ldap_response_done["protocolOp"]["searchResDone"] = search_result_done
        writer.write(encoder.encode(ldap_response_done))
        await writer.drain()
        print("Search response sent")

    async def handle_add_request(self, ldap_message, protocol_op, writer):
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

        ldap_response = LDAPMessage()
        ldap_response["messageID"] = ldap_message["messageID"]
        ldap_response["protocolOp"]["addResponse"] = add_response
        writer.write(encoder.encode(ldap_response))
        await writer.drain()
        print("Add response sent")

    async def handle_delete_request(self, ldap_message, protocol_op, writer):
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

        ldap_response = LDAPMessage()
        ldap_response["messageID"] = ldap_message["messageID"]
        ldap_response["protocolOp"]["delResponse"] = del_response
        writer.write(encoder.encode(ldap_response))
        await writer.drain()
        print(f"Delete response sent: {result}")

    async def handle_modify_request(self, ldap_message, protocol_op, writer):
        dn = str(protocol_op["modifyRequest"]["object"])
        print(f"Modify Request received: dn={dn}")

        changes = []
        for change in protocol_op["modifyRequest"]["changes"]:
            operation = LDAP_OPERATIONS[change["operation"]]
            attribute = str(change["modification"]["type"])
            values = [str(value) for value in change["modification"]["vals"]]
            changes.append(
                {"operation": operation, "attribute": attribute, "values": values}
            )

        ldap_changes = {}
        for change in changes:
            ldap_changes.setdefault(change["attribute"], []).append(
                (change["operation"], change["values"])
            )

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

        self.replicate_operation("modify", dn, ldap_changes)

        ldap_response = LDAPMessage()
        ldap_response["messageID"] = ldap_message["messageID"]
        ldap_response["protocolOp"]["modifyResponse"] = modify_response
        writer.write(encoder.encode(ldap_response))
        await writer.drain()
        print(f"Modify response sent: {result}")

    async def run(self, host="127.0.0.1", port=1389):
        server = await asyncio.start_server(self.handle_client, host, port)
        print(f"LDAP Middleware running on {host}:{port}")
        asyncio.create_task(self.periodic_tasks())
        async with server:
            await server.serve_forever()
