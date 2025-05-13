#pragma once

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
#include <stdio.h>
#include <stdlib.h>
#include "PubKeyMac.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/sha.h>
#include <openssl/asn1t.h>
#include <openssl/buffer.h>
#include <openssl/objects.h>
#include <time.h>
#include"Peer.h"
#define GMAC_TAG_LEN 16



class SymElementsRepository {
private:

public:

	SymElementsRepository();
	//void insertTransactionElementsIntoFile_SIGNED(Peer* peer, unsigned char* cipherText, long cipherText_len);

};