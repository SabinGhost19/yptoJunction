#pragma once

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct SymElements_st {
        ASN1_INTEGER* SymElementsId;
        ASN1_OCTET_STRING* SymKey;
        ASN1_OCTET_STRING* IV;
    } SymElements;

   

    DECLARE_ASN1_FUNCTIONS(SymElements);

#ifdef __cplusplus
}
#endif