import unittest
from unittest.mock import patch
from middleware.utils import discover_addresses


class TestUtils(unittest.TestCase):
    @patch("socket.getaddrinfo")
    def test_discover_addresses_dns_success(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(None, None, None, None, ("192.168.1.1", 0))]
        result = discover_addresses("test.com", ["192.168.1.2"])
        self.assertEqual(result, ["192.168.1.1"])


if __name__ == "__main__":
    unittest.main()
