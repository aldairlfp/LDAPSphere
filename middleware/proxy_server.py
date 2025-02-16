import asyncio
import os
import sqlite3
import time
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

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
        # Resolve partners dynamically
        self.raft_partners = discover_addresses(dns_domain, fallback_ips)
        self.raft_partners = [addr for addr in self.raft_partners if addr != raft_self]
        self.raft_partners = [
            f"{addr}:{port}" for addr in self.raft_partners if addr != f"{raft_self}"
        ]

        # Existing logic remains unchanged
        self.ldap_handler = LDAPRequestHandler(ldap_server, ldap_user, ldap_password)

        base_dir = os.path.dirname(os.path.abspath(__file__))

        self.setup_database(base_dir)
        self.local_logs = self.load_local_logs()
        self.logs = self.load_replicated_logs()

        self.replicator = LDAPReplicator(
            f"{raft_self}:{port}", self.raft_partners, self.logs
        )

        self.last_applied_index_file = os.path.join(
            base_dir, "..", f"last_applied_index_{get_local_address()}.txt"
        )
        self.last_applied_index = self.load_last_applied_index()

    def setup_database(self, base_dir):
        """Initialize SQLite databases for logs and local logs"""
        logs_file = os.path.join(
            base_dir, "..", f"replicated_logs_{get_local_address()}.db"
        )
        local_logs_file = os.path.join(
            base_dir, "..", f"local_logs_{get_local_address()}.db"
        )
        self.local_db = sqlite3.connect(local_logs_file, check_same_thread=False)
        self.replica_db = sqlite3.connect(logs_file, check_same_thread=False)

        with self.local_db:
            self.local_db.execute(
                """
                CREATE TABLE IF NOT EXISTS local_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation TEXT,
                    raw_request BLOB,
                    source_ip TEXT
                )
            """
            )

        with self.replica_db:
            self.replica_db.execute(
                """
                CREATE TABLE IF NOT EXISTS replicated_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_index INTEGER UNIQUE,
                    operation TEXT,
                    raw_request BLOB,
                    source_ip TEXT,
                    local_execution BOOLEAN DEFAULT 0
                )
            """
            )
        # with sqlite3.connect(
        #     os.path.join(base_dir, "..", f"failed_requests_{get_local_address()}.db")
        # ) as conn:
        #     cursor = conn.cursor()
        #     cursor.execute(
        #         "CREATE TABLE IF NOT EXISTS failed_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, request BLOB)"
        #     )

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
        """Retrieve all unreplicated operations"""
        with self.local_db:
            logs = self.local_db.execute(
                "SELECT id, operation, raw_request FROM local_logs"
            ).fetchall()
        return [
            {"id": idX, "operation": op, "raw_request": req} for idX, op, req in logs
        ]

    def load_replicated_logs(self):
        """Retrieve all replicated operations"""
        with self.replica_db:
            logs = self.replica_db.execute(
                "SELECT log_index, operation, raw_request FROM replicated_logs"
            ).fetchall()
        return [
            {"log_index": idx, "operation": op, "raw_request": req}
            for idx, op, req in logs
        ]

    def save_local_log(self, operation, raw_request):
        """Save an operation to the local log (before replication) and return the row added."""
        with self.local_db:
            cursor = self.local_db.execute(
                "INSERT INTO local_logs (operation, raw_request, source_ip) VALUES (?, ?, ?)",
                (operation, raw_request, get_local_address()),
            )
            row_id = cursor.lastrowid
        print(f"✅ Saved local operation: {operation}")
        return {"id": row_id, "operation": operation, "raw_request": raw_request}

    def save_replicated_log(self, log_index, operation, raw_request):
        """Save a replicated operation (after reaching consensus)"""
        with self.replica_db:
            self.replica_db.execute(
                "INSERT OR IGNORE INTO replicated_logs (log_index, operation, raw_request, source_ip) VALUES (?, ?, ?, ?)",
                (log_index, operation, raw_request, get_local_address()),
            )
        print(f"✅ Saved replicated operation {log_index}: {operation}")

    def apply_logs(self):
        """Applies all pending logs from the replicator and prints timing statistics."""
        min_time = float("inf")
        max_time = 0
        total_time = 0
        times = []
        logs = self.replicator.get_logs()
        for log_entry in logs:
            if log_entry["log_index"] > self.last_applied_index:
                start_time = time.time()

                self.apply_log(log_entry)
                self.last_applied_index = log_entry["log_index"]

                self.save_last_applied_index()

                self.save_replicated_log(
                    log_entry["log_index"],
                    log_entry["operation"],
                    log_entry["raw_request"],
                )

                end_time = time.time()
                operation_time = end_time - start_time
                times.append(operation_time)
                total_time += operation_time
                if operation_time < min_time:
                    min_time = operation_time
                if operation_time > max_time:
                    max_time = operation_time

        if times:
            avg_time = total_time / len(times)
            print(
                f"Operation times - Min: {min_time:.4f}s, Max: {max_time:.4f}s, Avg: {avg_time:.4f}s, Total: {total_time:.4f}s"
            )
        else:
            print("No operations to apply.")

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
            idX = log_entry["id"]
            operation = log_entry["operation"]
            raw_data = log_entry["raw_request"]

            print(f"📡 Replicating {operation} request...")

            # Forward the request to the real LDAP server again (simulating replay)
            response = self.replicator.replicate_operation(
                raw_data, operation, get_local_address()
            )

            # Clear log after replication
            self.local_logs.remove(log_entry)
            with self.local_db:
                self.local_db.execute("DELETE FROM local_logs WHERE id = ?", (idX,))

    def log_request_for_replication(self, operation, raw_data):
        """Logs and stores LDAP operations for replication"""

        saved_log = self.save_local_log(operation, raw_data)
        self.local_logs.append(saved_log)

        print(f"✅ Logged operation for replication: {operation}")

    async def periodic_tasks(self):
        """Execute periodic tasks such as applying logs."""
        while True:
            # print(self.replicator.get_logs())
            # Save the logs
            # self.retry_failed_requests()
            # self.replicator.addNodeToCluster("172.19.0.9:5000")
            self.replicator.forceLogCompaction()
            if not self.ldap_handler.check_ldap_availability():
                logging.error("LDAP server is not available. Exiting.")
                os._exit(1)
            if self.replicator.isReady():
                self.replicate_local_logs()

            print("Logs:")
            for log in self.replicator.get_logs():
                print({k: v for k, v in log.items() if k != "raw_request"})
            print(f"Lenght of logs: {len(self.replicator.get_logs())}")

            print("Local Logs:")
            for log in self.local_logs:
                print({k: v for k, v in log.items() if k != "raw_request"})

            if self.replicator._isLeader():
                print("I am the leader, managing local operations")
            else:
                print("I am a follower, applying replicated logs")
            self.apply_logs()
            await asyncio.sleep(5)

    async def handle_client(self, reader, writer):
        """
        Handles incoming LDAP client requests, ensuring complete message reads and preventing hangs.
        """
        client_address = writer.get_extra_info("peername")
        print(f"Connection from: {client_address}")

        try:
            while True:
                raw_data = b""

                # Read the complete LDAP message
                try:
                    while True:
                        chunk = await asyncio.wait_for(reader.read(4096), timeout=5.0)

                        if not chunk:  # Connection closed
                            print(f"Client {client_address} closed the connection.")
                            return

                        raw_data += chunk  # Append received chunk

                        # Try parsing just the operation name
                        try:
                            _, operation_name, _ = LDAPParser.parse(raw_data)
                            break  # Successfully identified operation
                        except Exception:
                            continue  # Keep reading until full message is received

                except asyncio.TimeoutError:
                    print(
                        f"⚠️ Timeout: No complete LDAP message received from {client_address}."
                    )
                    return  # Close the connection on timeout

                print(f"Received LDAP Operation: {operation_name}")  # Debugging

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
                    print("Error: No response received from LDAP server.")

        except Exception as e:
            print(f"⚠️ Error reading data: {str(e)}")

        finally:
            writer.close()
            await writer.wait_closed()
            print(f"Connection closed properly with {client_address}")

    async def run(self, host="127.0.0.1", port=1389):
        server = await asyncio.start_server(self.handle_client, host, port)
        print(f"LDAP Middleware running on {host}:{port}")
        asyncio.create_task(self.periodic_tasks())
        async with server:
            await server.serve_forever()
