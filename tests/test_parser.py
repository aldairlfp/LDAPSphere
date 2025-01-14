import pytest
from middleware.request_parser import LDAPRequestParser


def test_parse_add():
    command = """add dn: cn=testuser,dc=example,dc=com
objectClass: inetOrgPerson
cn: testuser
sn: surname
"""
    result = LDAPRequestParser.parse_command(command)
    expected = {
        "operation": "add",
        "dn": "cn=testuser,dc=example,dc=com",
        "attributes": {
            "objectClass": ["inetOrgPerson"],
            "cn": ["testuser"],
            "sn": ["surname"],
        },
    }
    assert result == expected


def test_parse_invalid_command():
    command = "invalid dn: cn=testuser,dc=example,dc=com"
    with pytest.raises(ValueError, match="Operación desconocida: invalid"):
        LDAPRequestParser.parse_command(command)
