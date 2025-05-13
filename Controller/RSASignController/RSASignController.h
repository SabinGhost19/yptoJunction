#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#define RSA_BITS 3072


class RSASignController {

private:
	
	void generateRSAKeys(RSA** key);
	void writRSAPrivateKeyToFile(RSA* key, const char* filename);
	void writRSAPublicKeyToFile(RSA* key, const char* filename);
	long signTransactionWithRSAPrivateKey(unsigned char** signedTransaction, RSA* key,
		unsigned char* input_data, long input_data_len);
public:
	
	void printRSAKey(RSA* key);
	RSA* readRsaPublicKey(const char* filename);
	RSA* readRsaPrivateKey(const char* filename);
	long signTransaction(unsigned char* transaction_raw_data, long transaction_raw_data_len,
		const char* privateRSAKeyFilename, const char* publicRSAKeyFilename, unsigned char** signed_transaction);

};

