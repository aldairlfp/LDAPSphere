import re


class LDAPRequestParser:
    @staticmethod
    def parse_command(command: str) -> dict:
        """
        Parsea una solicitud LDAP en formato estándar.
        """

        # Detectar la operación (add, modify, delete)
        operation_match = re.match(
            r"^(add|modify|delete) dn: (.+)", command, re.IGNORECASE
        )
        if not operation_match:
            raise ValueError(
                "Formato de solicitud no válido. Se esperaba 'add', 'modify' o 'delete'."
            )

        operation = operation_match.group(1).lower()
        dn = operation_match.group(2).strip()

        # Inicializar la estructura de la solicitud
        request = {"operation": operation, "dn": dn}

        # Procesar atributos para operaciones ADD o MODIFY
        if operation in ["add", "modify"]:
            attributes = {}
            current_attribute = None
            for line in command.splitlines():
                line = line.strip()

                # Saltar líneas vacías o no relacionadas
                if not line or line.startswith(operation):
                    continue

                # Detectar un nuevo atributo
                attribute_match = re.match(r"^(\w+): (.+)", line)
                if attribute_match:
                    current_attribute = attribute_match.group(1)
                    value = attribute_match.group(2)
                    attributes.setdefault(current_attribute, []).append(value)
                elif current_attribute:  # Continuación de un atributo multi-línea
                    attributes[current_attribute][-1] += f" {line}"

            request["attributes"] = attributes

        return request
