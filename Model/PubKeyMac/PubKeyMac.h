#pragma once

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct PubKeyMac_st {
        ASN1_PRINTABLESTRING* pubKeyName;
        ASN1_OCTET_STRING* macKey;
        ASN1_OCTET_STRING* macValue;
    } PubKeyMac;

  
    DECLARE_ASN1_FUNCTIONS(PubKeyMac);

#ifdef __cplusplus
}
#endif