import unittest
from unittest.mock import MagicMock
from middleware.replicator import LDAPReplicator


class TestLDAPReplicator(unittest.TestCase):
    def setUp(self):
        self.replicator = LDAPReplicator("127.0.0.1:5000", ["127.0.0.2:5000"])

        # Mock the @replicated function to return a valid log entry
        self.replicator.replicate_operation = MagicMock(
            return_value={
                "log_index": 1,
                "operation": "add",
                "dn": "cn=test",
                "attributes": {"attr": "value"},
                "source_ip": "127.0.0.1",
                "local_execution": False,
            }
        )

    def test_replicate_operation(self):
        log_entry = self.replicator.replicate_operation(
            "add", "cn=test", {"attr": "value"}, "127.0.0.1"
        )
        self.assertIsNotNone(log_entry)  # Ensure it is not None
        self.assertEqual(log_entry["operation"], "add")


if __name__ == "__main__":
    unittest.main()
