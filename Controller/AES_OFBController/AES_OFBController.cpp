#pragma once
#include "AES_OFBController.h"


AES_OFBController::AES_OFBController(std::string peerName)
{
    this->peerName = peerName;
    this->logger = new Logger();
}

unsigned char* AES_OFBController::aes_FANCY_OFB(const char* filename, const char* plainText, long plainText_len)
{
    FILE* fp = fopen(filename, "r");
    unsigned char* symelements_data_der_base64 = NULL;
    fseek(fp, 0, SEEK_END);
    int size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    symelements_data_der_base64 = (unsigned char*)OPENSSL_malloc(size + 1);

    fread(symelements_data_der_base64, size, 1, fp);
    symelements_data_der_base64[size] = '\0';


    unsigned char* symelements_data_der = (unsigned char*)OPENSSL_malloc(size);
    BIO* bio = BIO_new_mem_buf(symelements_data_der_base64, -1);
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    BIO_read(bio, symelements_data_der, size);
    BIO_flush(bio);

    this->logger->logAction(this->peerName, "reding symElementsDerData using at AES_FANCY_OFB");
    const unsigned char* symelements_data_der_const = symelements_data_der;

    SymElements* symElements = d2i_SymElements(NULL, &symelements_data_der_const, size);

    const unsigned char* IV_const = ASN1_STRING_get0_data(symElements->IV);
    unsigned char* IV = (unsigned char*)IV_const;
    printf("IV:\n");
    for (int i = 0; i < symElements->IV->length; i++) {
        printf("%02x ", IV[i]);
    }
    const unsigned char* symKey = ASN1_STRING_get0_data(symElements->SymKey);
    printf("\nSYMKEY:\n");
    for (int i = 0; i < symElements->SymKey->length; i++) {
        printf("%02x ", symKey[i]);
    }
    long symId = ASN1_INTEGER_get(symElements->SymElementsId);
    printf("SymElementsId: %ld\n", symId);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        printf("Eroare la crearea contextului pentru aes\n");
        exit(-1);
    }
    unsigned char* ciphertext = (unsigned char*)OPENSSL_malloc(plainText_len);
    unsigned char inv_iv[16];
    for (int i = 0; i < 16; i++)
    {
        inv_iv[i] = IV[15 - i];
    }
    unsigned char current_iv[16];
    memcpy(current_iv, IV, 16);
    int out_len;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, symKey, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        exit(-1);
    }

    this->logger->logAction(this->peerName, "begin custom interations in AES_FANCY_OFB");

    for (int i = 0; i < plainText_len; i += 16)
    {
        unsigned char keystream[16];
        int len = (plainText_len - i < 16) ? (plainText_len - i) : 16;
        if (EVP_EncryptUpdate(ctx, keystream, &out_len, current_iv, 16) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            exit(-1);
        }
        memcpy(current_iv, keystream, 16);

        for (int j = 0; j < 16; j++) keystream[j] ^= inv_iv[j];

        for (int j = 0; j < len; j++) {
            ciphertext[i + j] = plainText[i + j] ^ keystream[j];
        }

    }
    this->logger->logAction(this->peerName, "encrypt in AES_FANCY_OFB completed ");

    printf("CIPHER: \n");
    for (int i = 0; i < plainText_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    EVP_CIPHER_CTX_free(ctx);


    BIO_free_all(bio);
    OPENSSL_free(symelements_data_der);
    OPENSSL_free(symelements_data_der_base64);
    SymElements_free(symElements);
    return ciphertext;
}
