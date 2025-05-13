#pragma once
#include "ECDHController.h"


ECDHController::ECDHController(GMCController* gmcController)
{
    this->gmcController = gmcController;
    this->logger = new Logger();
}

int ECDHController::validate_public_key(const char* macFilename, EC_KEY* pubKey)
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

    // recompute GMAC
    long time_data = this->gmcController->get_time_diff();
    unsigned char* key = this->gmcController->generate_pbkdf2_key(time_data);
    unsigned char* tag = this->gmcController->generate_gcm_tag(pubkey_der, pubkey_der_len, key);
    printf("IN VALIDATE.....LETS COMPUTE:");
    printf("Generated tag: ");
    for (int i = 0; i < GMAC_TAG_LEN; i++) printf("%02x", tag[i]);
    printf("\n");

    // Compare GMAC tags
    int valid = (ASN1_STRING_length(PubKeyMac->macValue) == GMAC_TAG_LEN &&
        memcmp(ASN1_STRING_get0_data(PubKeyMac->macValue), tag, GMAC_TAG_LEN) == 0);


    OPENSSL_free(pubkey_der);
    free(key);
    free(tag);
    PubKeyMac_free(PubKeyMac);

    return valid;
}

int ECDHController::ecdh_handshake(const char* myPrivateKeyFilename, const char* peerPublicKeyFilename, const char* peerMacFilename, unsigned char* shared_secret, size_t* secret_len)
{
  
        // load personal private key
        FILE* priv_fp = fopen(myPrivateKeyFilename, "r");
        EC_KEY* my_key = PEM_read_ECPrivateKey(priv_fp, NULL, NULL, (void*)"pass");
        // load peer public key
        FILE* pub_fp = fopen(peerPublicKeyFilename, "r");
        EC_KEY* peer_key = PEM_read_EC_PUBKEY(pub_fp, NULL, NULL, NULL);
        fclose(pub_fp);

        this->logger->logAction(this->gmcController->getPeerName(), "validating GMC TAG at destination");
        // validate peer public key
        if (!validate_public_key(peerMacFilename, peer_key)) {
            fprintf(stderr, "Public key validation failed for %s\n", peerPublicKeyFilename);
            EC_KEY_free(my_key);
            EC_KEY_free(peer_key);
            return 0;
        }
        this->logger->logAction(this->gmcController->getPeerName(), "validation PASSED : GMC TAG at destination");

        const EC_GROUP* group = EC_KEY_get0_group(my_key);
        EC_POINT* shared_secret_ec_point = EC_POINT_new(group);

        BIGNUM* bn = NULL;
        BN_CTX* ctx = BN_CTX_new();

        EC_POINT_mul(group, shared_secret_ec_point, bn, EC_KEY_get0_public_key(peer_key),
            EC_KEY_get0_private_key(my_key), ctx);

        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();
        if (!x || !y) {
            //free all res above
            exit(-1);
        }

        EC_POINT_get_affine_coordinates(group, shared_secret_ec_point, x, y, ctx);

        BN_bn2binpad(x, shared_secret, 32);
        BN_bn2binpad(y, shared_secret + 32, 32);

        this->logger->logAction(this->gmcController->getPeerName(), "extracting the SHARED SECRET in ECDH operation");

        //free all
        *secret_len = 64;

        // perform ECDH
        //*secret_len = ECDH_compute_key(shared_secret, 64, EC_KEY_get0_public_key(peer_key), my_key, NULL);

        EC_KEY_free(my_key);
        EC_KEY_free(peer_key);
        return 1;
    
}
