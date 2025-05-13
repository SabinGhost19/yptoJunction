#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
#pragma once
#include <stdio.h>
#include "NetworkContext.h"
#include "SystemContext.h"
#include <openssl/applink.c>



int main() {
    
    
    Logger* logger = new Logger();
    try {
        int numPeers;
        std::map<std::string, int> peerMap;
        std::vector<Transaction_struct> transactions;
        // parse input file
        SystemContext::parseInputFile("transactions.txt", numPeers, peerMap, transactions);

        // create peers
        auto peers = SystemContext::MockPeer(peerMap, transactions);

        std::map<int, Peer*> idToPeer;
        for (const auto& peer : peers) {
            idToPeer[peer->getPeerId()] = peer.get();
        }

        // print peer details
        for (size_t i = 0; i < peers.size(); ++i) {
            std::cout << "Peer " << (i + 1) << ":\n";
            SystemContext::PrintPeer(peers[i].get());
            std::cout << "\n";
        }


        // for each transaction (sender and receiver)
        for (const auto& transaction : transactions) {
            Peer* sender = idToPeer[transaction.senderId];
            Peer* receiver = idToPeer[transaction.receiverId];
            
            
            //prep after algo-------------------
            SystemContext::exchangeFilenameInfos(sender, receiver);
            SystemContext::exchangeFilenameInfos(receiver, sender);
            SystemContext::computeFileNamesPerPeer(sender, receiver);
            std::string BOTHPeers = "";
            strcat((char*)BOTHPeers.c_str(), sender->name.c_str());
            strcat((char*)BOTHPeers.c_str(), "->to->");
            strcat((char*)BOTHPeers.c_str(), receiver->name.c_str());
            //------------------------

            if (sender && receiver) {
                // ensure first peers have a controller
                logger->logAction(BOTHPeers, "-------------START OF TRANSACTION-------------");


                //pass the controllers with prev ctx peer data
                GMCController *senderGMCController= NetworkContext::__simulateECDHKeyGen_(sender);
                GMCController *receiverGMCController = NetworkContext::__simulateECDHKeyGen_(receiver);

                // perform key exchange between sender and receiver
                NetworkContext::__simulateECDHGenExchange_perPeer(sender, senderGMCController);
                NetworkContext::__simulateECDHGenExchange_perPeer(receiver, receiverGMCController);



                // generate symmetric keys
                NetworkContext::__simulateSymKeyGen(sender);
                NetworkContext::__simulateSymKeyGen(receiver);

                // perform encryption
                NetworkContext::simulateENCRYPTION_AES_FANCY_OFB(sender);
                NetworkContext::simulateENCRYPTION_AES_FANCY_OFB(receiver);
                
               

                logger->logAction(BOTHPeers, "-------------END OF TRANSACTION-------------");
            }
            else {
                std::cerr << "Warning: Sender or Receiver not found for transaction: Sender ID "
                    << transaction.senderId << ", Receiver ID " << transaction.receiverId << std::endl;
            }
        }

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    delete logger;

    return 0;
}
