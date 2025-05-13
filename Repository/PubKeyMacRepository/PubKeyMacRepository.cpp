#pragma once
#include "PubKeyMacRepository.h"

 PubKeyMacRepository::PubKeyMacRepository()
{
     this->key = EC_KEY_new_by_curve_name(NID_secp256k1);
     EC_KEY_generate_key(this->key);
}
int PubKeyMacRepository::readECPublicKey()
{
    return 0;
}
int PubKeyMacRepository::convertToEC_KEYToDer(unsigned char** ECpubkey_der) {
   
    return i2d_EC_PUBKEY(this->key, ECpubkey_der);
}

void PubKeyMacRepository::setAESPass(const char* password, long password_len) {
    if (password_len >= 120) {
        fprintf(stderr, "Error: Password length exceeds 119 characters\n");
        exit(-1);
    }
    memcpy(this->password, password, password_len);
    this->password[password_len] = '\0'; 
}
void PubKeyMacRepository::insertECPublicKey()
{
    FILE* publicFp = fopen(this->publicKeyFilename, "w");
 
    //stocare cheie publica in clar
    PEM_write_EC_PUBKEY(publicFp, this->key);

    fclose(publicFp);
}

void PubKeyMacRepository::setKeysFilename(const char* macpublicKeyFilename,long macpublicKeyFilename_len,const char* publicKeyFilename, long publicKeyFilename_len, const char* privateKeyFilename, long privateKeyFilename_len) {
    
    if (publicKeyFilename_len > 20 || privateKeyFilename_len > 20) {
        fprintf(stderr, "Error: Filename length exceeds 20 characters\n");
        exit(-1);
    }

    this->privateKeyFilename = new char[21];
    this->publicKeyFilename = new char[21];
    this->macpublicKeyFilename = new char[21];

    memcpy(this->privateKeyFilename, privateKeyFilename, publicKeyFilename_len);
    this->privateKeyFilename[publicKeyFilename_len] = '\0';
    memcpy(this->publicKeyFilename, publicKeyFilename, privateKeyFilename_len);
    this->publicKeyFilename[privateKeyFilename_len] = '\0';
    memcpy(this->macpublicKeyFilename, macpublicKeyFilename, macpublicKeyFilename_len);
    this->macpublicKeyFilename[macpublicKeyFilename_len] = '\0';
}
void PubKeyMacRepository::insertECPrivateKey() {
    printf("Opening file: %s\n", this->privateKeyFilename);
    if (!this->privateKeyFilename) {
        fprintf(stderr, "Error: privateKeyFilename is null\n");
        exit(-1);
    }

    FILE* privateFp = fopen(this->privateKeyFilename, "wb");
    if (privateFp == NULL) {
        fprintf(stderr, "Error opening file: %s\n", this->privateKeyFilename);
        exit(-1);
    }

    if (!this->key) {
        fprintf(stderr, "Error: EC_KEY is null\n");
        fclose(privateFp);
        exit(-1);
    }

    if (!this->password || strlen((const char*)this->password) == 0) {
        fprintf(stderr, "Error: Password is null or empty\n");
        fclose(privateFp);
        exit(-1);
    }

    const unsigned char* password = (const unsigned char*)this->password;
    if (!PEM_write_ECPrivateKey(privateFp, this->key, EVP_aes_256_cbc(), password, strlen((const char*)password), NULL, NULL)) {
        fprintf(stderr, "Error writing EC private key: %s\n", ERR_error_string(ERR_get_error(), NULL));
        fclose(privateFp);
        exit(-1);
    }

    fclose(privateFp);
}

void PubKeyMacRepository::insertPubKeyMacIntoFile(unsigned char* key_pbkdf2, unsigned char* tag) {
  
    PubKeyMac* PubKeyMac = PubKeyMac_new();

    ASN1_STRING_set(PubKeyMac->pubKeyName, this->publicKeyFilename, strlen(this->publicKeyFilename));
    ASN1_STRING_set(PubKeyMac->macKey, key_pbkdf2, 32);
    ASN1_STRING_set(PubKeyMac->macValue, tag, GMAC_TAG_LEN);


    unsigned char* der_data = NULL;
    int der_data_len = i2d_PubKeyMac(PubKeyMac, &der_data);
    //--------------------------
    char macfilename[256];
    sprintf(macfilename, "%s.mac",this->macpublicKeyFilename);
    FILE* tagFile = fopen(macpublicKeyFilename, "wb");
    fwrite(der_data, 1, der_data_len, tagFile);
    fclose(tagFile);

    OPENSSL_free(der_data);
    PubKeyMac_free(PubKeyMac);

}


