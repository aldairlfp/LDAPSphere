from pyasn1.codec.ber import decoder
from ldap3.protocol.rfc4511 import LDAPMessage


class LDAPParser:
    """Handles LDAP request parsing and identification"""

    @staticmethod
    def parse(raw_data):
        """
        Decodes an LDAP message from raw data.

        Args:
            raw_data (bytes): The raw LDAP request received.

        Returns:
            tuple: (parsed LDAPMessage object, operation name, error if any)
        """
        try:
            ldap_message, rest = decoder.decode(raw_data, asn1Spec=LDAPMessage())
            protocol_op = ldap_message["protocolOp"]
            operation_name = protocol_op.getName()
            return ldap_message, operation_name, None
        except Exception as e:
            return None, None, f"Error decoding LDAP message: {str(e)}"
