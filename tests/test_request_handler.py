import unittest
from unittest.mock import patch, MagicMock
from middleware.request_handler import LDAPRequestHandler


class TestLDAPRequestHandler(unittest.TestCase):
    def setUp(self):
        self.ldap_handler = LDAPRequestHandler(
            "ldap://test.com", "cn=admin,dc=test,dc=com", "password"
        )

    @patch("ldap3.Connection")
    def test_validate_credentials_success(self, mock_connection):
        mock_conn = MagicMock()
        mock_conn.bind.return_value = True
        mock_connection.return_value = mock_conn
        result = self.ldap_handler.validate_credentials(
            "cn=user,dc=test,dc=com", "password"
        )
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
