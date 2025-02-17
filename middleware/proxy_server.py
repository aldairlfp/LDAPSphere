import asyncio
import os
import pickle
import logging
import socket
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException

from middleware.ldap_parser import LDAPParser
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
    ):
        self.port = port
        # Existing logic remains unchanged
        self.ldap_handler = LDAPRequestHandler(ldap_server, ldap_user, ldap_password)

        base_dir = os.path.dirname(os.path.abspath(__file__))

        self.data_path = os.path.join(base_dir, "..", f"data_{get_local_address()}.pkl")

        local_logs, last_applied_index = self.load_data()

        self.local_logs = local_logs
        self.last_applied_index = last_applied_index

        # Resolve partners dynamically
        self.raft_partners = discover_addresses(dns_domain, fallback_ips)
        self.raft_partners = [addr for addr in self.raft_partners if addr != raft_self]
        self.raft_partners = [
            f"{addr}:{port}" for addr in self.raft_partners if addr != f"{raft_self}"
        ]

        self.possible_joins = []

        self.replicator = LDAPReplicator(f"{raft_self}:{port}", self.raft_partners)

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
        for i, log_entry in enumerate(logs, self.last_applied_index + 1):
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

        self.ldap_handler.forward_request(log_entry["raw_request"])

    def replicate_local_logs(self):
        """Replicates pending local operations."""
        for log_entry in self.local_logs:
            operation = log_entry["operation"]
            raw_data = log_entry["raw_request"]

            logging.info(f"Replicating {operation} request...")

            # Forward the request to the real LDAP server again (simulating replay)
            self.replicator.replicate_operation(
                raw_data, operation, get_local_address()
            )

            # Clear log after replication
            self.local_logs.remove(log_entry)

    def log_request_for_replication(self, operation, raw_data):
        """Logs and stores LDAP operations for replication"""

        self.local_logs.append(
            {
                "operation": operation,
                "raw_request": raw_data,
            }
        )
        self.save_data()

        logging.info(f"Logged operation for replication: {operation}")

    async def broadcast_presence(self):
        """Periodically announce this node's presence via UDP."""
        while True:
            try:
                message = f"NODE_ANNOUNCE {get_local_address()}:{self.port}"
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

                try:
                    sock.sendto(message.encode(), ("255.255.255.255", 5005))
                    logging.info("Broadcasted node presence")
                except Exception as e:
                    logging.error(f"Error broadcasting presence: {e}")
                finally:
                    sock.close()  # Ensure the socket is closed in all cases

            except Exception as e:
                logging.error(f"Unexpected error in broadcast_presence: {e}")

            await asyncio.sleep(10)  # Prevents excessive looping

    async def listen_for_nodes(self):
        """Listen for incoming node announcements and add them dynamically."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Reuse address
        sock.bind(("0.0.0.0", 5005))

        while True:
            try:
                sock.settimeout(3)  # Prevents indefinite blocking
                data, addr = await asyncio.to_thread(
                    sock.recvfrom, 1024
                )  # Non-blocking
                message = data.decode()

                if message.startswith("NODE_ANNOUNCE"):
                    _, node_address = message.split(" ")
                    if (
                        node_address not in self.raft_partners
                        and node_address not in self.possible_joins
                        and node_address != f"{get_local_address()}:5000"
                    ):
                        self.possible_joins.append(node_address)
                        logging.info(f"🔍 Detected new node: {node_address}")

            except socket.timeout:
                await asyncio.sleep(2)  # Avoids CPU overuse

            except asyncio.TimeoutError:
                logging.warning("Timeout while waiting for node announcements")
                await asyncio.sleep(2)

            except Exception as e:
                logging.error(f"Error receiving node announcement: {e}")
                await asyncio.sleep(5)  # Prevent rapid retries

        sock.close()
        logging.info("Socket closed properly")

    async def periodic_tasks(self):
        """Execute periodic tasks such as applying logs."""
        while True:
            self.replicator.forceLogCompaction()

            for node in self.possible_joins:
                self.replicator.addNodeToCluster(node)
                self.raft_partners.append(node)

            self.possible_joins.clear()

            if not self.ldap_handler.check_ldap_availability():
                logging.error("LDAP server is not available. Exiting.")
                os._exit(1)
            if self.replicator.isReady():
                self.replicate_local_logs()

            # print("Logs:")
            # for log in self.replicator.get_logs():
            #     print({k: v for k, v in log.items() if k != "raw_request"})
            print(f"Length of logs: {len(self.replicator.get_logs())}")

            # print("Local Logs:")
            # for log in self.local_logs:
            #     print({k: v for k, v in log.items() if k != "raw_request"})

            if self.replicator._isLeader():
                print("I am the leader, managing local operations")
            else:
                print("I am a follower, applying replicated logs")

            print(f"Raft Partners: {self.raft_partners}")
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

                # Read the complete LDAP message
                try:
                    while True:
                        chunk = await asyncio.wait_for(reader.read(4096), timeout=5.0)

                        if not chunk:  # Connection closed
                            logging.info(
                                f"Client {client_address} closed the connection."
                            )
                            return

                        raw_data += chunk  # Append received chunk

                        # Try parsing just the operation name
                        try:
                            _, operation_name, _ = LDAPParser.parse(raw_data)
                            break  # Successfully identified operation
                        except Exception:
                            continue  # Keep reading until full message is received

                except asyncio.TimeoutError:
                    logging.warning(
                        f"Timeout: No complete LDAP message received from {client_address}."
                    )
                    return  # Close the connection on timeout

                logging.info(f"Received LDAP Operation: {operation_name}")  # Debugging

                # Forward the request to the real LDAP server
                response = self.ldap_handler.forward_request(raw_data)

                # Save request for replication if it's an ADD, MODIFY, or DELETE operation
                if operation_name in ["addRequest", "modifyRequest", "delRequest"]:
                    self.log_request_for_replication(operation_name, raw_data)

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

        # Start gossip-based discovery
        asyncio.create_task(self.broadcast_presence())
        asyncio.create_task(self.listen_for_nodes())

        async with server:
            await server.serve_forever()
