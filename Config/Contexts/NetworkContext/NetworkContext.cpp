#pragma once
#include"NetworkContext.h"
#include"SystemContext.h"
#include"TransactionRepository.h"
#include"Logger.h"

namespace NetworkContext {

    void simulateCommunicationINIT(Peer* sender, Peer* listener) {

        sender->setStateSender();

        std::cout << "=== Network Communication Simulation ===\n";
        std::cout << "Sender (Peer ID: " << sender->getPeerId() << ") initiates communication:\n";
        std::cout << "  Sending transaction...\n";
        std::cout << "  Subject: " << (sender->getSubject() ? (char*)sender->getSubject() : "None") << "\n";
        std::cout << "  Transaction Data: " << (sender->getTransactionData() ? (char*)sender->getTransactionData() : "None") << "\n";

        std::cout << "Listener (Peer ID: " << listener->getPeerId() << ") is ready to receive:\n";
        std::cout << "  Status: Listening for incoming transactions...\n";
        std::cout << "=======================================\n";
    }

    GMCController* __simulateECDHKeyGen_(Peer* peer) {
        PubKeyMacRepository* pubkeymacRepository_first = new PubKeyMacRepository();
        pubkeymacRepository_first->setKeysFilename(peer->publicRepo.macECPublicKeyfilename, 20, peer->publicRepo.ECPublicKeyfilename, 20, peer->privateRepo.ECPrivateKeyfilename, 20);
        pubkeymacRepository_first->setAESPass("pass", 4);
        GMCController* gmcController = new GMCController(pubkeymacRepository_first,peer->name);
        gmcController->generate_EC_key_pairs();

        return gmcController;
    }

    void __simulateECDHGenExchange_perPeer(Peer* peer, GMCController* gmcController) {


        ECDHController* ecdhController = new ECDHController(gmcController);

        unsigned char* shared_secret = (unsigned char*)OPENSSL_malloc(64);

        size_t secret_len_a;
        if (ecdhController->ecdh_handshake(peer->privateRepo.ECPrivateKeyfilename,
            peer->privateRepo.peer_ECPublicKeyfilename, peer->privateRepo.peer_macECPublicKeyfilename,
            shared_secret, &secret_len_a)) {

            printf("Entity A shared secret (%zu bytes): ", secret_len_a);
            for (size_t i = 0; i < secret_len_a; i++) printf("%02x", shared_secret[i]);
            printf("\n");
        }
        peer->privateRepo.sharedSecret = shared_secret;

        delete ecdhController;
    }


    void __simulateSymKeyGen(Peer* peer) {

        SymKeyController* symKeyController = new SymKeyController(peer->name);

        unsigned char* symKey_a = NULL;
        unsigned char* iv_a = NULL;
        int random_ID = SystemContext::generateRandomId();
        symKeyController->generate_SimKey(peer->privateRepo.sharedSecret, &symKey_a, &iv_a);
        symKeyController->insertValuesToASN1Struct(peer->publicRepo.SymKeyfilename, random_ID, symKey_a, iv_a);
        delete symKeyController;
    }

    unsigned char* simulateENCRYPTION_AES_FANCY_OFB(Peer* peer) {

        Logger* logger = new Logger();
        AES_OFBController* aesofbController = new AES_OFBController(peer->name);
        long lenght = strlen((const char*)peer->getTransactionData());
        unsigned char* cipherText =
            //compute fancy ciper and get the CipherText
            aesofbController->aes_FANCY_OFB(peer->publicRepo.SymKeyfilename,
                (const char*)peer->getTransactionData(), lenght);

        delete aesofbController;


        //write transaction with ASN1 in der file
        unsigned char* bufferToBeSigned = NULL;
        Transaction* transaction = NULL;
        logger->logAction(peer->name, "computeTransaction: parsing and seting ASN1 structure data for buffer to be signed");
        TransactionRepository* transactionRepository = new TransactionRepository();
        long bufferToBeSigned_len = transactionRepository->computeTransaction(&bufferToBeSigned
            , peer, cipherText, lenght);

        logger->logAction(peer->name, "signing transaction ALL data");

        long signed_transaction_len = 0;
        unsigned char* signedTransaction = SimulateTransactionSign(peer, bufferToBeSigned, bufferToBeSigned_len, &signed_transaction_len);

        //careful here
        logger->logAction(peer->name, "inserting Transaction Elemnts into Filed, SIGNED DATA");
        transactionRepository->insertTransactionElementsIntoFile_SIGNED(peer, signedTransaction, signed_transaction_len);

        delete transactionRepository;
        delete logger;

        return nullptr;

    }


    unsigned char* SimulateTransactionSign(Peer* peer, unsigned char* bufferToBeSigned, long bufferToBeSigned_len, long* signed_transaction_len) {
        //read transaction and then sign it
        
         Logger* logger = new Logger();
         RSASignController* rsasignController = new RSASignController();

         logger->logAction(peer->name, "generate RSA keys, create files, sign data with RSA privKey");
        unsigned char* signedTransaction = NULL;
        *signed_transaction_len = rsasignController->signTransaction((unsigned char*)bufferToBeSigned, 18,
            peer->privateRepo.rsaPublicKeyFilename, peer->privateRepo.rsaPrivateKeyFilename, &signedTransaction);

        delete rsasignController;
        delete logger;
        return signedTransaction;
    }

    void simulateFinishingDataAndSendingIt() {

    }



}