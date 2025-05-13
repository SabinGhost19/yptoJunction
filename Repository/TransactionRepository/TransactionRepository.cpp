#include "TransactionRepository.h"
#include"SymElements.h"
#include"Transaction.h"
#include"SystemContext.h"

TransactionRepository::TransactionRepository()
{
}

void TransactionRepository::insertTransactionElementsIntoFile_SIGNED(Peer*peer,unsigned char*signedTransaction,long signedTransaction_len){
	
	FILE* trFp = fopen(peer->publicRepo.Transactionfilename, "wb");

	ASN1_STRING_set(this->transactionToBeSigned->TransactionSign, signedTransaction, signedTransaction_len);
	
	unsigned char* derDataToBeInserted = NULL;
	long derDataToBeInserted_len=i2d_Transaction(this->transactionToBeSigned, &derDataToBeInserted);

	fwrite(derDataToBeInserted, 1, derDataToBeInserted_len, trFp);

	fclose(trFp);


	//delete this->transactionToBeSigned;

}

long TransactionRepository::computeTransaction( unsigned char** bufferToBeSigned_extern, Peer* peer, unsigned char* cipherText, long cipherText_len){

        // Open the file
        FILE* symFp = fopen(peer->publicRepo.SymKeyfilename, "r");
        if (!symFp) {
            fprintf(stderr, "Failed to open file: %s\n", peer->publicRepo.SymKeyfilename);
            return -1; // Or handle the error appropriately
        }

        // Get file size
        fseek(symFp, 0, SEEK_END);
        long symElementsData_len = ftell(symFp);
        if (symElementsData_len <= 0) {
            fprintf(stderr, "File is empty or invalid: %s\n", peer->publicRepo.SymKeyfilename);
            fclose(symFp);
            return -1;
        }
        fseek(symFp, 0, SEEK_SET);

        // Read the Base64-encoded data
        unsigned char* symElementsDataBase64 = (unsigned char*)OPENSSL_malloc(symElementsData_len + 1);
        if (!symElementsDataBase64) {
            fprintf(stderr, "Failed to allocate memory for Base64 data\n");
            fclose(symFp);
            return -1;
        }
        size_t readBytes = fread(symElementsDataBase64, 1, symElementsData_len, symFp);
        fclose(symFp);
        if (readBytes != static_cast<size_t>(symElementsData_len-1)) {
            fprintf(stderr, "Failed to read file: %s\n", peer->publicRepo.SymKeyfilename);
            OPENSSL_free(symElementsDataBase64);
            return -1;
        }
        symElementsDataBase64[symElementsData_len] = '\0'; // Null-terminate for safety

        // Decode Base64 to raw DER
        BIO* bio = BIO_new_mem_buf(symElementsDataBase64, symElementsData_len);
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);

        unsigned char* symElementsData = (unsigned char*)OPENSSL_malloc(symElementsData_len); // Allocate buffer for DER data
        if (!symElementsData) {
            fprintf(stderr, "Failed to allocate memory for DER data\n");
            BIO_free_all(bio);
            OPENSSL_free(symElementsDataBase64);
            return -1;
        }

        int derLen = BIO_read(bio, symElementsData, symElementsData_len);
        BIO_free_all(bio);
        OPENSSL_free(symElementsDataBase64);

        if (derLen <= 0) {
            fprintf(stderr, "Failed to decode Base64 data\n");
            OPENSSL_free(symElementsData);
            return -1;
        }

        // Decode DER data to SymElements
        const unsigned char* symElementsDataConst = symElementsData;
        SymElements* sym = d2i_SymElements(NULL, &symElementsDataConst, derLen);
        if (!sym) {
            fprintf(stderr, "Failed to parse SymElements: %s\n", ERR_error_string(ERR_get_error(), NULL));
            OPENSSL_free(symElementsData);
            return -1;
        }

        // Access the SymElementsId
        long SymElementId = ASN1_INTEGER_get(sym->SymElementsId);
        if (SymElementId < 0) {
            fprintf(stderr, "Failed to get SymElementsId\n");
            SymElements_free(sym);
            OPENSSL_free(symElementsData);
            return -1;
        }

	long trnsactionId = SystemContext::generateRandomId();
    


	this->transactionToBeSigned = Transaction_new();
    this->transactionToBeSigned->SymElementsId = ASN1_INTEGER_new();
    this->transactionToBeSigned->TransactionId= ASN1_INTEGER_new();
    this->transactionToBeSigned->Subject = ASN1_OCTET_STRING_new();
    this->transactionToBeSigned->EncryptedData = ASN1_OCTET_STRING_new();
    this->transactionToBeSigned->SenderId = ASN1_INTEGER_new();
    this->transactionToBeSigned->ReceiverId = ASN1_INTEGER_new();
    this->transactionToBeSigned->TransactionSign = ASN1_OCTET_STRING_new();



	ASN1_INTEGER_set(this->transactionToBeSigned->SymElementsId, SymElementId);
	ASN1_INTEGER_set(this->transactionToBeSigned->TransactionId, trnsactionId);
	ASN1_STRING_set(this->transactionToBeSigned->Subject, peer->getSubject(), strlen((const char*)peer->getSubject()));
	ASN1_STRING_set(this->transactionToBeSigned->EncryptedData, cipherText, cipherText_len);
	ASN1_INTEGER_set(this->transactionToBeSigned->SenderId, peer->getPeerId());
	ASN1_INTEGER_set(this->transactionToBeSigned->ReceiverId, peer->getCommPeerId());

	long offset = 0;
	unsigned char*bufferToBeSigned = (unsigned char*)OPENSSL_malloc(1200);
	memcpy(bufferToBeSigned + offset, this->transactionToBeSigned->SymElementsId, sizeof(long));
	offset += sizeof(long);

	memcpy(bufferToBeSigned + offset, &trnsactionId, sizeof(long));
	offset += sizeof(long);

	memcpy(bufferToBeSigned + offset, peer->getSubject(), strlen((const char*)peer->getSubject()));
	offset += strlen((const char*)peer->getSubject());

	memcpy(bufferToBeSigned + offset, cipherText, cipherText_len);
	offset += cipherText_len;

	memcpy(bufferToBeSigned + offset, this->transactionToBeSigned->SenderId, sizeof(long));
	offset += sizeof(long);

	memcpy(bufferToBeSigned + offset, this->transactionToBeSigned->ReceiverId, sizeof(long));
	offset += sizeof(long);

	*bufferToBeSigned_extern = (unsigned char*)OPENSSL_realloc(bufferToBeSigned, offset+1);

	

	return offset;
}

