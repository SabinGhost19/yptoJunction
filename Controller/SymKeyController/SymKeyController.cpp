#include "SymKeyController.h"
#pragma once


   

SymKeyController::SymKeyController(std::string peerName)
{
    this->peerName = peerName;
    this->logger = new Logger();
}

void SymKeyController::generate_SimKey(unsigned char* shared_secret, unsigned char** symKey, unsigned char** iv)
{
    this->logger->logAction(this->peerName, "generating SIMKEY");
    unsigned char* x = (unsigned char*)OPENSSL_malloc(32);
    unsigned char* y = (unsigned char*)OPENSSL_malloc(32);

    memcpy(x, shared_secret, 32);
    memcpy(y, shared_secret + 32, 32);

    unsigned char hash_x[32];
    SHA256(x, 32, hash_x);

    unsigned char hash_x_first[16];
    unsigned char hash_x_second[16];

    memcpy(hash_x_first, hash_x, 16);
    memcpy(hash_x_second, hash_x + 16, 16);

    //sym left
    unsigned char sym_left[16];
    for (int i = 0; i < 16; i++) {
        sym_left[i] = hash_x_second[i] ^ hash_x_first[i];
    }

    this->logger->logAction(this->peerName, "generating SIMKEY: PBKDF2 HMAC with SHA384");

    unsigned char sym_right[48];
    PKCS5_PBKDF2_HMAC((const char*)y, 32, NULL, 0, 10000, EVP_sha384(), 48, sym_right);


    *symKey = (unsigned char*)OPENSSL_malloc(16);
    *iv = (unsigned char*)OPENSSL_malloc(16);

    this->logger->logAction(this->peerName, "generating SIMKEY: computing LEFT--RIGHT side of symKey");

    for (int i = 0; i < 16; i++) {
        (*symKey)[i] = sym_left[i] ^ sym_right[i];
    }
    for (int i = 0; i < 16; i++) {
        (*iv)[i] = sym_right[i + 16];
    }

}

void SymKeyController::insertValuesToASN1Struct(const char* filenameSymKeyElements, int ID, unsigned char* SymKey, unsigned char* IV)
{
    FILE* fp = fopen(filenameSymKeyElements, "w");

    SymElements* symStruct = SymElements_new();
    symStruct->SymElementsId = ASN1_INTEGER_new();
    symStruct->IV = ASN1_OCTET_STRING_new();
    symStruct->SymKey = ASN1_OCTET_STRING_new();

    ASN1_INTEGER_set(symStruct->SymElementsId, ID);
    ASN1_OCTET_STRING_set(symStruct->IV, IV, 16);
    ASN1_OCTET_STRING_set(symStruct->SymKey, SymKey, 16);

    unsigned char* symElements_data_der = NULL;
    int symElements_data_der_len = i2d_SymElements(symStruct, &symElements_data_der);

    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    BIO_write(bio, symElements_data_der, symElements_data_der_len);
    BIO_flush(bio);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);
    char* base64 = (char*)malloc(bptr->length + 1);
    memcpy(base64, bptr->data, bptr->length);
    base64[bptr->length] = '\0';

    //fwrite(base64, bptr->length + 1, 1, fp);
    fprintf(fp, "%s", base64);
    fclose(fp);
    printf("\nBASE64 ENC: %s\n", base64);
    BIO_free_all(bio);
    free(base64);
    OPENSSL_free(symElements_data_der);
    SymElements_free(symStruct);
}
