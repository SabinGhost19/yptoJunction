#pragma once
#include "PubKeyMac.h"
#include"GMCController.h"


class ECDHController {
private:
    GMCController* gmcController = NULL;
    Logger* logger = nullptr;
public:

    ECDHController(GMCController* gmcController);
    int validate_public_key(const char* macFilename, EC_KEY* pubKey);

     int ecdh_handshake(const char* myPrivateKeyFilename, const char* peerPublicKeyFilename,
         const char* peerMacFilename, unsigned char* shared_secret, size_t* secret_len);


};