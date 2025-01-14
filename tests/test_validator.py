import pytest
from middleware.request_validator import LDAPRequestValidator


def test_validate_valid_request():
    request = {
        "operation": "add",
        "dn": "cn=testuser,dc=example,dc=com",
        "attributes": {
            "objectClass": ["inetOrgPerson"],
            "cn": "testuser",
            "sn": "surname",
        },
    }
    # Esto no debe lanzar excepciones
    LDAPRequestValidator.validate_request(request)


def test_validate_missing_dn():
    request = {
        "operation": "add",
        "attributes": {
            "objectClass": ["inetOrgPerson"],
            "cn": "testuser",
            "sn": "surname",
        },
    }
    with pytest.raises(ValueError, match="Falta el campo obligatorio: dn"):
        LDAPRequestValidator.validate_request(request)


def test_validate_invalid_operation():
    request = {
        "operation": "invalid",
        "dn": "cn=testuser,dc=example,dc=com",
        "attributes": {
            "objectClass": ["inetOrgPerson"],
            "cn": "testuser",
            "sn": "surname",
        },
    }
    with pytest.raises(ValueError, match="Operación no soportada: invalid"):
        LDAPRequestValidator.validate_request(request)
