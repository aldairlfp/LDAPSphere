from pyasn1.codec.ber import decoder
from ldap3.protocol.rfc4511 import LDAPMessage
from pyasn1.type.univ import OctetString


class LDAPParser:
    """Handles LDAP request parsing and identification"""

    @staticmethod
    def parse(raw_data):
        """
        Decodes an LDAP message from raw data.

        Args:
            raw_data (bytes): The raw LDAP request received.

        Returns:
            tuple: (parsed LDAPMessage object, operation name, user_dn, password or None)
        """
        try:
            # Attempt to decode the LDAP message
            ldap_message, _ = decoder.decode(raw_data, asn1Spec=LDAPMessage())

            # Extract protocol operation
            protocol_op = ldap_message.getComponentByName("protocolOp")
            if protocol_op is None:
                return None, None, None, "Error: protocolOp is missing in LDAP message"

            operation_name = protocol_op.getName()
            user_dn = None
            password = None

            if operation_name == "bindRequest":
                bind_request = protocol_op.getComponentByName("bindRequest")
                if bind_request:
                    user_dn = str(bind_request.getComponentByName("name"))

                    auth = bind_request.getComponentByName("authentication")
                    if isinstance(auth.getComponent(), OctetString):
                        password = auth.getComponent().asOctets().decode("utf-8")
                    else:
                        password = None  # Non-password authentication (e.g., SASL)

            return ldap_message, operation_name, user_dn, password

        except Exception as e:
            return None, None, None, f"Error decoding LDAP message: {str(e)}"
