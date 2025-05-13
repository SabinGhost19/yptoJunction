#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include "SymElements.h"
#include"Logger.h"
#include<string>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/sha.h>
#define GMAC_TAG_LEN 16
#define TARGET_TIME "050505050505Z"


class AES_OFBController {

    std::string peerName;
    Logger* logger = nullptr;
public:
    AES_OFBController(std::string peerName);
    unsigned char* aes_FANCY_OFB(const char* filename, const char* plainText, long plainText_len);
    

};