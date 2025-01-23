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
        """Registra y propaga operaciones LDAP con un índice de log."""
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
            print(f"Error al serializar el log: {log_entry} -> {e}")

        print(f"Operación replicada: {log_entry}")
        return log_entry

    def get_logs(self):
        """Devuelve los logs registrados en el nodo"""
        return self.__logs

    def get_last_applied_index(self):
        """Devuelve el índice de la última operación aplicada"""
        return self.__log_index

    def load_logs(self):
        """Carga los logs persistidos desde el archivo"""
        if os.path.exists(self.__logs_file):
            with open(self.__logs_file, "r") as f:
                logs = json.load(f)
                self.__logs = logs.get("logs", [])
                if self.__logs:
                    self.__log_index = self.__logs[-1]["log_index"]
                print("Logs cargados desde el archivo.")
        else:
            print("No se encontraron logs persistidos. Comenzando desde cero.")

    def save_logs(self):
        """Guarda los logs en el archivo."""
        try:
            with open(self.__logs_file, "w") as f:
                json.dump({"logs": self.__logs}, f)
                print("Logs guardados en el archivo.")
        except Exception as e:
            print(f"Error guardando los logs: {e}")
