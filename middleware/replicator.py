import json
import os
import logging
from pysyncobj import SyncObj, replicated, SyncObjConf


class LDAPReplicator(SyncObj):
    def __init__(self, self_address, partner_addresses):
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            f"logs_data_dump.bin",
        )
        path1 = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            f"logs_data.bin",
        )
        conf = SyncObjConf(
            dynamicMembershipChange=True, fullDumpFile=path, journalFile=path1
        )
        super().__init__(
            self_address,
            partner_addresses,
            conf,
        )
        self.__logs = []
        self.__log_index = 0

    @replicated
    def replicate_operation(
        self, raw_request, operation, source_ip, local_execution=False
    ):
        """Register a new operation in the logs"""
        self.__log_index += 1
        log_entry = {
            "log_index": self.__log_index,
            "raw_request": raw_request,
            "operation": operation,
            "source_ip": source_ip,
            "local_execution": local_execution,
        }
        self.__logs.append(log_entry)

        logging.info(f"Replicated operation: {self.__log_index}")
        return log_entry

    def get_logs(self):
        """Returns the logs registered in the node"""
        return self.__logs

    def get_last_applied_index(self):
        """Returns the index of the last operation applied"""
        return self.__log_index
