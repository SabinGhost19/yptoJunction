#pragma once

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct Transaction_st {
        ASN1_INTEGER* TransactionId;
        ASN1_OCTET_STRING* Subject;
        ASN1_INTEGER* SenderId;
        ASN1_INTEGER* ReceiverId;
        ASN1_INTEGER* SymElementsId;
        ASN1_OCTET_STRING* EncryptedData;
        ASN1_OCTET_STRING* TransactionSign;
    } Transaction;


    DECLARE_ASN1_FUNCTIONS(Transaction);

#ifdef __cplusplus
}
#endif