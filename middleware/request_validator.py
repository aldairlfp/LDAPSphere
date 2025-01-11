import re


class LDAPRequestValidator:
    @staticmethod
    def validate_request_structure(request):
        required_fields = ["operation", "dn"]
        supported_operations = ["add", "modify", "delete", "search"]

        for field in required_fields:
            if field not in request:
                raise ValueError(f"Falta el campo obligatorio: {field}")

        if request["operation"] not in supported_operations:
            raise ValueError(f"Operación no soportada: {request['operation']}")

        if request["operation"] in ["add", "modify"] and "attributes" not in request:
            raise ValueError("La operación requiere el campo 'attributes'.")

        if request["operation"] == "search" and "filter" not in request:
            raise ValueError("La operación 'search' requiere el campo 'filter'.")

    @staticmethod
    def validate_dn(dn):
        dn_regex = r"^([a-zA-Z]+=.+,)*[a-zA-Z]+=.+$"
        if not re.match(dn_regex, dn):
            raise ValueError(f"DN inválido: {dn}")

    @staticmethod
    def validate_attributes(attributes):
        if not isinstance(attributes, dict):
            raise ValueError("Los atributos deben ser un diccionario.")
        for key, value in attributes.items():
            if not isinstance(key, str) or not (
                isinstance(value, str) or isinstance(value, list)
            ):
                raise ValueError(f"Atributo inválido: {key} -> {value}")

    @staticmethod
    def validate_request(request):
        LDAPRequestValidator.validate_request_structure(request)
        LDAPRequestValidator.validate_dn(request["dn"])
        if "attributes" in request:
            LDAPRequestValidator.validate_attributes(request["attributes"])
