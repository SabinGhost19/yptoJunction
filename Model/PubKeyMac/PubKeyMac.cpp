#include "PubKeyMac.h"

ASN1_SEQUENCE(PubKeyMac) = {
      ASN1_SIMPLE(PubKeyMac, pubKeyName, ASN1_PRINTABLESTRING),
      ASN1_SIMPLE(PubKeyMac, macKey, ASN1_OCTET_STRING),
      ASN1_SIMPLE(PubKeyMac, macValue, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(PubKeyMac);


IMPLEMENT_ASN1_FUNCTIONS(PubKeyMac)