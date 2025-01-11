from middleware.server import LDAPMiddleware
from middleware.request_handler import LDAPRequestHandler
import os

if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()

    ldap_url = os.getenv("LDAP_URL")
    admin_dn = os.getenv("LDAP_ADMIN_DN")
    admin_password = os.getenv("LDAP_ADMIN_PASSWORD")
    port = int(os.getenv("PORT", 1389))

    handler = LDAPRequestHandler(ldap_url, admin_dn, admin_password)
    server = LDAPMiddleware("127.0.0.1", port, handler)
    server.run()
