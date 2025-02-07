import json
import os
from pysyncobj import SyncObj, replicated


class LDAPReplicator(SyncObj):
    def __init__(self, self_address, partner_addresses, logs):
        super().__init__(self_address, partner_addresses)
        self.__logs = logs
        self.__log_index = 0

    @replicated
    def replicate_operation(self, raw_request, source_ip, local_execution=False):
        """Register a new operation in the logs"""
        self.__log_index += 1
        log_entry = {
            "log_index": self.__log_index,
            "raw_request": raw_request,
            "source_ip": source_ip,
            "local_execution": local_execution,
        }
        self.__logs.append(log_entry)

        print(f"Replicated operation: {self.__log_index}")
        return log_entry

    def get_logs(self):
        """Returns the logs registered in the node"""
        return self.__logs

    def get_last_applied_index(self):
        """Returns the index of the last operation applied"""
        return self.__log_index
