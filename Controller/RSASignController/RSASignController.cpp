#include "RSASignController.h"

void RSASignController::generateRSAKeys(RSA** key)
{
    *key = RSA_new();
    while (!RSA_generate_key_ex(*key, RSA_BITS, NULL, NULL)) { printf("RSA try again to generate key\n"); }

}

void RSASignController::writRSAPrivateKeyToFile(RSA* key, const char* filename)
{
    FILE* fp = fopen(filename, "w");

    if (!PEM_write_RSAPrivateKey(fp, key, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Failed to weite privateRSAKey into file");
        exit(-1);
    }
    fclose(fp);
}

void RSASignController::writRSAPublicKeyToFile(RSA* key, const char* filename)
{
    FILE* fp = fopen(filename, "w");
    if (!PEM_write_RSAPublicKey(fp, key)) {
        fprintf(stderr, "Failed to weite publicRSAKey into file");
        exit(-1);
    }
    fclose(fp);
}

void RSASignController::printRSAKey(RSA* key)
{
    if (key) {
        RSA_print_fp(stdout, key, 0);
    }
}

RSA* RSASignController::readRsaPublicKey(const char* filename)
{
    RSA* pubkey = RSA_new();
    FILE* fp = fopen(filename, "rb");

    PEM_read_RSAPublicKey(fp, &pubkey, NULL, NULL);
    fclose(fp);
    if (pubkey == NULL) {
        fprintf(stderr, "No content in reading RSA PRIVATE KEY\n");
        exit(-1);
    }

    return pubkey;
}

RSA* RSASignController::readRsaPrivateKey(const char* filename)
{
    RSA* privkey = RSA_new();
    FILE* fp = fopen(filename, "rb");

    PEM_read_RSAPrivateKey(fp, &privkey, NULL, NULL);
    fclose(fp);
    if (privkey == NULL) {
        fprintf(stderr, "No content in reading RSA PRIVATE KEY\n");
        exit(-1);
    }
    return privkey;
}

long RSASignController::signTransaction(unsigned char* transaction_raw_data, long transaction_raw_data_len, const char* privateRSAKeyFilename, const char* publicRSAKeyFilename, unsigned char** signed_transaction)
{
        RSA* key = NULL;
        this->generateRSAKeys(&key);
        this->writRSAPrivateKeyToFile(key, privateRSAKeyFilename);

        this->writRSAPublicKeyToFile(key, publicRSAKeyFilename);

        long signed_len = this->signTransactionWithRSAPrivateKey(signed_transaction, key, transaction_raw_data, transaction_raw_data_len);
        return signed_len;
}

long RSASignController::signTransactionWithRSAPrivateKey(unsigned char** signedTransaction, RSA* key, unsigned char* input_data, long input_data_len)
{
    int len = RSA_size(key);
    *signedTransaction = new unsigned char[len];
    memset(*signedTransaction, 0, len);

    int bytes_signed = RSA_private_encrypt(input_data_len, input_data, *signedTransaction, key, RSA_PKCS1_PADDING);
    if (bytes_signed < 1) {
        fprintf(stderr, "RSA Sign failed\n");
        exit(-1);
    }
    return bytes_signed;
}
