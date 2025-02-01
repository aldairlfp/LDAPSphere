import asyncio
import unittest
from middleware.proxy_server import LDAPProxyServer
from middleware.utils import get_local_address


class TestLDAPProxyIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server1 = LDAPProxyServer(
            ldap_server="ldap://localhost:389",
            ldap_user="cn=admin,dc=test,dc=com",
            ldap_password="1234",
            raft_self=f"{get_local_address()}",
            dns_domain="",
            fallback_ips=["127.0.0.2"],
        )
        cls.server2 = LDAPProxyServer(
            ldap_server="ldap://localhost:389",
            ldap_user="cn=admin,dc=test,dc=com",
            ldap_password="1234",
            raft_self=f"{get_local_address()}",
            dns_domain="",
            fallback_ips=["127.0.0.1"],
        )
        cls.loop = asyncio.get_event_loop()
        cls.loop.create_task(cls.server1.run("127.0.0.1", 1389))
        cls.loop.create_task(cls.server2.run("127.0.0.2", 1389))

    def test_server_running(self):
        self.assertTrue(self.server1)
        self.assertTrue(self.server2)


if __name__ == "__main__":
    unittest.main()
