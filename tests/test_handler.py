import pytest
from middleware.request_handler import LDAPRequestHandler


@pytest.fixture
def live_handler():
    # Replace these with your actual LDAP server details
    handler = LDAPRequestHandler(
        ldap_url="ldap://127.0.0.1",  # Use your server's address if different
        admin_dn="cn=admin,dc=example,dc=com",
        admin_password="1234",  # Replace with your admin password
    )
    return handler


def test_handle_add(live_handler):
    request = {
        "operation": "add",
        "dn": "cn=testuser,dc=example,dc=com",
        "attributes": {
            "objectClass": ["inetOrgPerson"],
            "cn": "testuser",
            "sn": "surname",
        },
    }

    # Perform the operation
    result = live_handler.handle_request(request)

    # Validate the result
    assert result["description"] == "success"

    # Optionally, clean up by deleting the test entry
    cleanup_request = {"operation": "delete", "dn": "cn=testuser,dc=example,dc=com"}
    live_handler.handle_request(cleanup_request)
