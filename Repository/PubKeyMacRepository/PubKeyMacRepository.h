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

#define GMAC_TAG_LEN 16
#define TARGET_TIME "050505050505Z"



class PubKeyMacRepository {
private:
	unsigned char password[120];
	char* publicKeyFilename = NULL;
	char* privateKeyFilename = NULL;
	char* macpublicKeyFilename = NULL;
	EC_KEY* key = NULL;
public:

	PubKeyMacRepository();
	int convertToEC_KEYToDer(unsigned char** ECpubkey_der);
	//setters and getters
	void setAESPass(const char*password,long password_len);

	void setKeysFilename(const char* macpublicKeyFilename, long macpublicKeyFilename_len,
		const char* publicKeyFilename, long publicKeyFilename_len, const char* privateKeyFilename,
		long privateKeyFilename_len);


	void insertPubKeyMacIntoFile(unsigned char* key_pbkdf2, unsigned char* tag);
	int readECPublicKey();
	void insertECPublicKey();
	void insertECPrivateKey();


};