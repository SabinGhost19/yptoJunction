#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
#include <stdio.h>
#include <stdlib.h>
#include "SymElements.h"
#include <string.h>
#include<string>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/sha.h>
#include"Logger.h"
#pragma once
#define GMAC_TAG_LEN 16
#define TARGET_TIME "050505050505Z"



class SymKeyController {
    std::string peerName;
    Logger* logger = nullptr;
public:

    SymKeyController(std::string peerName);
    void  generate_SimKey(unsigned char* shared_secret,
        unsigned char** symKey, unsigned char** iv);

    void insertValuesToASN1Struct(const char* filenameSymKeyElements,
        int ID, unsigned char* SymKey, unsigned char* IV);
    
};