class LDAPRequestParser:
    @staticmethod
    def parse_command(command):
        lines = command.strip().split("\n")
        operation_line = lines[0].strip()

        # Detectar operación
        if operation_line.startswith("add"):
            return LDAPRequestParser.parse_add(lines)
        elif operation_line.startswith("modify"):
            return LDAPRequestParser.parse_modify(lines)
        elif operation_line.startswith("delete"):
            return LDAPRequestParser.parse_delete(lines)
        elif operation_line.startswith("search"):
            return LDAPRequestParser.parse_search(lines)
        else:
            raise ValueError(f"Operación desconocida: {operation_line}")

    @staticmethod
    def parse_add(lines):
        dn = lines[0].split(": ")[1].strip()
        attributes = {}
        for line in lines[1:]:
            if line.strip():
                key, value = line.split(": ", 1)
                attributes.setdefault(key, []).append(value.strip())
        return {"operation": "add", "dn": dn, "attributes": attributes}

    @staticmethod
    def parse_modify(lines):
        dn = lines[0].split(": ")[1].strip()
        changes = {}
        current_attr = None
        for line in lines[1:]:
            if line.startswith("replace:"):
                current_attr = line.split(": ")[1].strip()
                changes[current_attr] = []
            elif current_attr and line.strip():
                changes[current_attr].append(line.split(": ", 1)[1].strip())
        return {"operation": "modify", "dn": dn, "changes": changes}

    @staticmethod
    def parse_delete(lines):
        dn = lines[0].split(": ")[1].strip()
        return {"operation": "delete", "dn": dn}

    @staticmethod
    def parse_search(lines):
        base = lines[0].split(": ")[1].strip()
        filter_line = [line for line in lines if line.startswith("filter:")][0]
        filter_value = filter_line.split(": ", 1)[1].strip()
        attributes_line = [line for line in lines if line.startswith("attributes:")]
        attributes = (
            attributes_line[0].split(": ")[1].strip().split(",")
            if attributes_line
            else []
        )
        return {
            "operation": "search",
            "base": base,
            "filter": filter_value,
            "attributes": attributes,
        }
