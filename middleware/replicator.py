import json
import os
from pysyncobj import SyncObj, replicated


class LDAPReplicator(SyncObj):
    def __init__(
        self,
        self_address,
        partner_addresses,
        logs_file="logs.json",
    ):
        super().__init__(self_address, partner_addresses)
        self.__logs = []
        self.__log_index = 0

        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.__logs_file = os.path.join(base_dir, "..", logs_file)

        # Cargar logs persistidos desde el archivo
        self.load_logs()

    @replicated
    def replicate_operation(
        self, operation, dn, attributes, source_ip, local_execution=False
    ):
        """Register a new operation in the logs"""
        self.__log_index += 1
        log_entry = {
            "log_index": self.__log_index,
            "operation": operation,
            "dn": dn,
            "attributes": attributes,
            "source_ip": source_ip,
            "local_execution": local_execution,
        }
        self.__logs.append(log_entry)

        # Verifica que el log sea serializable
        try:
            import pickle

            pickle.dumps(log_entry)
        except Exception as e:
            print(f"Error serializing the log: {log_entry} -> {e}")

        print(f"Replicated operation: {log_entry}")
        return log_entry

    def get_logs(self):
        """Returns the logs registered in the node"""
        return self.__logs

    def get_last_applied_index(self):
        """Returns the index of the last operation applied"""
        return self.__log_index

    def load_logs(self):
        """Load persisted logs from file"""
        if os.path.exists(self.__logs_file):
            with open(self.__logs_file, "r") as f:
                logs = json.load(f)
                self.__logs = logs.get("logs", [])
                if self.__logs:
                    self.__log_index = self.__logs[-1]["log_index"]
                print("Logs loaded from file.")
        else:
            print("No persisted logs were found. Starting from scratch.")

    def save_logs(self):
        """Save the logs to the file."""
        try:
            with open(self.__logs_file, "w") as f:
                json.dump({"logs": self.__logs}, f)
                print("Logs saved in the file.")
        except Exception as e:
            print(f"Error saving logs: {e}")
