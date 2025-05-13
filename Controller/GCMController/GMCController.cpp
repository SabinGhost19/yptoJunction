#include "GMCController.h"
#pragma once

long GMCController::get_time_diff()
{
    ASN1_TIME* target = ASN1_TIME_new();
    if (!target || !ASN1_TIME_set_string(target, TARGET_TIME)) {
        ASN1_TIME_free(target);
        return 0;
    }

    struct tm tm;
    time_t now = time(NULL);
    gmtime_s(&tm, &now);

    ASN1_TIME* current = ASN1_TIME_new();
    if (!current || !ASN1_TIME_set(current, mktime(&tm))) {
        ASN1_TIME_free(current);
        ASN1_TIME_free(target);
        return 0;
    }

    int days, secs;
    if (!ASN1_TIME_diff(&days, &secs, current, target)) {
        ASN1_TIME_free(current);
        ASN1_TIME_free(target);
        return 0;
    }

    long diff = labs((long)days * 86400 + secs);

    ASN1_TIME_free(target);
    ASN1_TIME_free(current);
    return diff;
}




GMCController::GMCController(PubKeyMacRepository* pubkeymacRepository,std::string peerName)
{
    this->pubkeymacRepository = pubkeymacRepository;
    this->logger = new Logger();
    this->peerName = peerName;
}

void GMCController::generate_EC_key_pairs()
{
    this->logger->logAction(this->peerName,"generating ECPrivKey and inserting it into file");
    this->pubkeymacRepository->insertECPrivateKey();
    this->pubkeymacRepository->insertECPublicKey();
    
    unsigned char* ECpubkey_der = NULL;
    int len_ECpubkey_der_len=this->pubkeymacRepository->convertToEC_KEYToDer(&ECpubkey_der);


    printf("pubkey_der_len: %d\n", len_ECpubkey_der_len);
    printf("pubkey_der: ");
    for (int i = 0; i < len_ECpubkey_der_len; i++) printf("%02x", ECpubkey_der[i]);
    printf("\n");


    this->logger->logAction(this->peerName, "generating PBKDF2 Key");
    long time_data = this->get_time_diff();
    printf("time_data: %ld\n", time_data);
    unsigned char* key_pbkdf2 = generate_pbkdf2_key(time_data);


    this->logger->logAction(this->peerName, "generating GMC TAG Key");
    unsigned char* tag = generate_gcm_tag(ECpubkey_der, len_ECpubkey_der_len, key_pbkdf2);
    printf("Generated tag: ");
    for (int i = 0; i < GMAC_TAG_LEN; i++) printf("%02x", tag[i]);
    printf("\n");




    //mac needs to be stored in the next der format:
    // 
    //PubKeyMac: = Sequence{ 
        //PubKeyName: PrintableString
        //MACKey : OCTET STRING
        //MACValue : OCTET STRING
    //}
    this->logger->logAction(this->peerName, "inserting GMC TAG into file");
    pubkeymacRepository->insertPubKeyMacIntoFile(key_pbkdf2, tag);

    OPENSSL_free(ECpubkey_der);
    free(key_pbkdf2);
    free(tag);
    

}

int GMCController::validate_public_key(const char* macFilename, EC_KEY* pubKey)
{
    // load PubKeyMac from file
    FILE* macFile = fopen(macFilename, "rb");
    fseek(macFile, 0, SEEK_END);
    long mac_len = ftell(macFile);
    fseek(macFile, 0, SEEK_SET);
    unsigned char* mac_data = (unsigned char*)malloc(mac_len);
    fread(mac_data, 1, mac_len, macFile);
    fclose(macFile);

    const unsigned char* p = mac_data;
    PubKeyMac* PubKeyMac = d2i_PubKeyMac(NULL, &p, mac_len);
    free(mac_data);


    // convert public key to DER
    unsigned char* pubkey_der = NULL;
    int pubkey_der_len = i2d_EC_PUBKEY(pubKey, &pubkey_der);


    printf("pubkey_der_len: %d\n", pubkey_der_len);
    printf("pubkey_der: ");
    for (int i = 0; i < pubkey_der_len; i++) printf("%02x", pubkey_der[i]);
    printf("\n");



    //this->logger->logAction(this->peerName, "recomputing the GMC TAG at destination");
    // recompute GMAC
    long time_data = get_time_diff();
    unsigned char* key = generate_pbkdf2_key(time_data);
    unsigned char* tag = generate_gcm_tag(pubkey_der, pubkey_der_len, key);
    printf("IN VALIDATE.....LETS COMPUTE:");
    printf("Generated tag: ");

   /* for (int i = 0; i < GMAC_TAG_LEN; i++) printf("%02x", tag[i]);
    printf("\n");*/

    // Compare GMAC tags
    //this->logger->logAction(this->peerName, "validating GMC TAG at destination");
    int valid = (ASN1_STRING_length(PubKeyMac->macValue) == GMAC_TAG_LEN &&
        memcmp(ASN1_STRING_get0_data(PubKeyMac->macValue), tag, GMAC_TAG_LEN) == 0);


    OPENSSL_free(pubkey_der);
    free(key);
    free(tag);
    PubKeyMac_free(PubKeyMac);

    return valid;
}



unsigned char* GMCController::generate_gcm_tag(unsigned char* data, long data_len, const unsigned char* key)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "CTX ERROR GENERATE");
        exit(-1);
    }
    const unsigned char iv[12] = { 0 };
    //generare in 2 pasi
    //init structura interna a cifrului
    EVP_EncryptInit(ctx, EVP_aes_128_gcm(), NULL, NULL);
    //actulizeaza cheia si iv-ul
    EVP_EncryptInit(ctx, NULL, key, iv);


    //criptare
    int len;
    EVP_EncryptUpdate(ctx, NULL, &len, data, data_len);

    EVP_EncryptFinal(ctx, NULL, &len);

    //save in tag
    unsigned char* tag = (unsigned char*)malloc(GMAC_TAG_LEN);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GMAC_TAG_LEN, tag);

    EVP_CIPHER_CTX_free(ctx);


    return tag;

}

unsigned char* GMCController::generate_pbkdf2_key(long time_data)
{
    //here aes_key_len: 32
    unsigned char* key = (unsigned char*)malloc(32 * sizeof(unsigned char));

    //for endianess
    unsigned char time_buff[8];
    for (int i = 0; i < 8; i++) {
        time_buff[i] = (time_data >> (i * 8)) & 0xFF;
    }

    //here aes_key_len: 32
    PKCS5_PBKDF2_HMAC((const char*)time_buff, sizeof(long), NULL, 0, 1000, EVP_sha3_256(), 32, key);


    return key;

}

std::string GMCController::getPeerName()
{
    return this->peerName;
}
