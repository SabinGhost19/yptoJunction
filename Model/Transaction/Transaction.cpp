#include "Transaction.h"

ASN1_SEQUENCE(Transaction) = {
       ASN1_SIMPLE(Transaction, TransactionId, ASN1_INTEGER),
       ASN1_SIMPLE(Transaction, Subject, ASN1_OCTET_STRING),
       ASN1_SIMPLE(Transaction, SenderId, ASN1_INTEGER),
       ASN1_SIMPLE(Transaction, ReceiverId, ASN1_INTEGER),
       ASN1_SIMPLE(Transaction, SymElementsId, ASN1_INTEGER),
       ASN1_SIMPLE(Transaction, EncryptedData, ASN1_OCTET_STRING),
       ASN1_SIMPLE(Transaction, TransactionSign, ASN1_OCTET_STRING)
      
} ASN1_SEQUENCE_END(Transaction);

IMPLEMENT_ASN1_FUNCTIONS(Transaction)