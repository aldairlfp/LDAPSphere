import asyncio
import os
import pickle
import logging
import socket
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

from middleware.ldap_parser import LDAPParser
from middleware.replicator import LDAPReplicator
from middleware.request_handler import LDAPRequestHandler
from middleware.utils import get_local_address

from logger import logger as logging

LDAP_OPERATIONS = {0: MODIFY_ADD, 1: MODIFY_DELETE, 2: MODIFY_REPLACE}


class LDAPProxyServer:
    def __init__(
        self,
        ldap_server,
        ldap_user,
        ldap_password,
        raft_self,
        fallback_ips=[],
        port=5000,
    ):
        self.port = port
        # Existing logic remains unchanged
        self.ldap_handler = LDAPRequestHandler(ldap_server, ldap_user, ldap_password)

        base_dir = os.path.dirname(os.path.abspath(__file__))

        self.data_path = os.path.join(base_dir, "..", f"data.pkl")

        local_logs, last_applied_index = self.load_data()

        self.local_logs = local_logs
        self.last_applied_index = last_applied_index

        # Resolve partners dynamically
        if len(fallback_ips) == 0:
            raft_partners = []
        else:
            fallback_ips = [addr for addr in fallback_ips if addr != raft_self]
            raft_partners = [
                f"{addr}:{port}" for addr in fallback_ips if addr != f"{raft_self}"
            ]

        self.replicator = LDAPReplicator(f"{raft_self}:{port}", raft_partners)

        self.authenticated_users = {}

        logging.info("LDAPProxyServer initialized")

    def load_data(self):
        """Retrieve all unreplicated operations"""
        try:
            with open(self.data_path, "rb") as f:
                data = pickle.load(f)
        except FileNotFoundError:
            data = {
                "local_logs": [],
                "last_applied_index": 0,
            }
            with open(self.data_path, "wb") as f:
                pickle.dump(data, f)
        logging.info(f"Loaded data from {self.data_path}")
        return data["local_logs"], data["last_applied_index"]

    def save_data(self):
        """Save an operation to the local log (before replication) and return the row added."""
        try:
            with open(self.data_path, "wb") as f:
                data = {
                    "local_logs": self.local_logs,
                    "last_applied_index": self.last_applied_index,
                }
                pickle.dump(data, f)
        except Exception as e:
            logging.error(f"Error saving data: {e}")
        logging.info(f"Saved data to {self.data_path}")
        return data["local_logs"], data["last_applied_index"]

    def apply_logs(self):
        """Applies all pending logs from the replicator and prints timing statistics."""
        logs = self.replicator.get_logs()
        logs_count = 0
        for log_entry in logs[self.last_applied_index :]:
            self.apply_log(log_entry)
            self.last_applied_index = log_entry["log_index"]

            self.save_data()
            logs_count += 1
            if logs_count == 50:
                break

    def apply_log(self, log_entry):
        """Applies a single operation to the LDAP server."""
        if (
            log_entry["local_execution"]
            and log_entry["source_ip"] == get_local_address()
        ):
            return

        self.ldap_handler.forward_request(
            log_entry["raw_request"], log_entry["user_dn"], log_entry["password"]
        )

    def replicate_local_logs(self):
        """Replicates pending local operations."""
        for log_entry in self.local_logs:
            operation = log_entry["operation"]
            raw_data = log_entry["raw_request"]

            logging.info(f"Replicating {operation} request...")

            # Forward the request to the real LDAP server again (simulating replay)
            self.replicator.replicate_operation(
                raw_data,
                operation,
                log_entry["user_dn"],
                log_entry["password"],
                get_local_address(),
            )

            # Clear log after replication
            self.local_logs.remove(log_entry)

    def log_request_for_replication(self, operation, raw_data, user_dn, password):
        """Logs and stores LDAP operations for replication"""

        self.local_logs.append(
            {
                "operation": operation,
                "raw_request": raw_data,
                "user_dn": user_dn,
                "password": password,
            }
        )
        self.save_data()

        logging.info(f"Logged operation for replication: {operation}")

    async def periodic_tasks(self):
        """Execute periodic tasks such as applying logs."""
        while True:
            self.replicator.forceLogCompaction()

            if not self.ldap_handler.check_ldap_availability():
                logging.error("LDAP server is not available. Exiting.")
                print("LDAP server is not available. Exiting.")
                os._exit(1)

            if self.replicator.isReady():
                self.replicate_local_logs()

            print("Logs:")
            for log in self.replicator.get_logs():
                print({k: v for k, v in log.items() if k != "raw_request"})
            print(f"Length of logs: {len(self.replicator.get_logs())}")

            # print("Local Logs:")
            # for log in self.local_logs:
            #     print({k: v for k, v in log.items() if k != "raw_request"})

            if self.replicator._isLeader():
                print("I am the leader, managing local operations")
            else:
                print("I am a follower, applying replicated logs")

            # print(f"Cluster: {self.raft_partners}")
            # print(f"Status -> {self.replicator.getStatus()}")

            self.apply_logs()
            await asyncio.sleep(5)

    async def handle_client(self, reader, writer):
        """
        Handles incoming LDAP client requests, ensuring proper request reading and connection closure.
        """
        client_address = writer.get_extra_info("peername")
        logging.info(f"Connection from: {client_address}")

        try:
            while True:
                raw_data = b""
                timeout = 5.0  # Adjust timeout if necessary

                try:
                    # Read the first byte to check the BER tag (should be 0x30 for LDAP messages)
                    first_byte = await asyncio.wait_for(reader.readexactly(1), timeout)
                    if not first_byte:
                        logging.info(f"Client {client_address} closed the connection.")
                        return

                    raw_data += first_byte

                    # Read the next byte, which contains length information
                    length_byte = await asyncio.wait_for(reader.readexactly(1), timeout)
                    raw_data += length_byte

                    message_length = length_byte[0]  # Initial assumption

                    if message_length >= 0x80:
                        # Multi-byte length format
                        length_bytes_count = message_length & 0x7F
                        length_data = await asyncio.wait_for(
                            reader.readexactly(length_bytes_count), timeout
                        )
                        raw_data += length_data
                        message_length = int.from_bytes(length_data, "big")

                    logging.debug(f"Expected LDAP message length: {message_length}")

                    # Read the full message body dynamically
                    while len(raw_data) < (
                        message_length + 2
                    ):  # +2 accounts for first two bytes read
                        chunk = await asyncio.wait_for(reader.read(4096), timeout)
                        if not chunk:
                            logging.warning(
                                f"Connection closed prematurely from {client_address}."
                            )
                            return
                        raw_data += chunk

                    logging.debug(
                        f"Complete LDAP message received ({len(raw_data)} bytes)"
                    )

                except asyncio.TimeoutError:
                    logging.warning(
                        f"Timeout: No complete LDAP message received from {client_address}."
                    )
                    return  # Close the connection on timeout
                except asyncio.IncompleteReadError:
                    logging.warning(
                        f"Incomplete LDAP message received from {client_address}."
                    )
                    return  # Connection lost before full message was received

                # Try parsing just the operation name
                try:
                    _, operation_name, user_dn, password = LDAPParser.parse(raw_data)
                except Exception:
                    continue  # Keep reading until full message is received

                except asyncio.TimeoutError:
                    logging.warning(
                        f"Timeout: No complete LDAP message received from {client_address}."
                    )
                    return  # Close the connection on timeout

                logging.info(f"Received LDAP Operation: {operation_name}")  # Debugging

                if operation_name == "bindRequest":
                    self.authenticated_users[client_address[0]] = (user_dn, password)

                # Forward the request to the real LDAP server
                response = self.ldap_handler.forward_request(
                    raw_data,
                    self.authenticated_users[client_address[0]][0],
                    self.authenticated_users[client_address[0]][1],
                )

                # Save request for replication if it's an ADD, MODIFY, or DELETE operation
                if operation_name in ["addRequest", "modifyRequest", "delRequest"]:
                    self.log_request_for_replication(
                        operation_name,
                        raw_data,
                        self.authenticated_users[client_address[0]][0],
                        self.authenticated_users[client_address[0]][1],
                    )

                # Send response back to the client
                if response:
                    writer.write(response)
                    await writer.drain()
                else:
                    logging.error("Error: No response received from LDAP server.")

        except Exception as e:
            logging.error(f"Error reading data: {str(e)}")

        finally:
            writer.close()
            await writer.wait_closed()
            logging.info(f"Connection closed properly with {client_address}")

    async def run(self, host="127.0.0.1", port=1389):
        server = await asyncio.start_server(self.handle_client, host, port)
        logging.info(f"LDAP Middleware running on {host}:{port}")
        asyncio.create_task(self.periodic_tasks())

        async with server:
            await server.serve_forever()
