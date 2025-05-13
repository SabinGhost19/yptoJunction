#pragma once
#include "SystemContext.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <limits>
#include <cstring>
#include <stdexcept>

namespace SystemContext {
    
    void exchangeFilenameInfos(Peer* sender, Peer* receiver)
    {
        memcpy(sender->privateRepo.peer_ECPublicKeyfilename, receiver->publicRepo.ECPublicKeyfilename, 21);
        memcpy(sender->privateRepo.peer_macECPublicKeyfilename, receiver->publicRepo.macECPublicKeyfilename, 21);

    }
    int generateRandomId() {
        static std::mt19937 rng(static_cast<unsigned int>(time(nullptr)));
        std::uniform_int_distribution<int> dist(1000, 9999);
        return dist(rng);
    }

    void formatFilename(char* dest, size_t destSize, const std::string& idStr, const std::string& fieldName, const std::string& ext) {
        const int fixedLength = 20;
        const int maxFieldLength = 11;

        std::string temp = idStr + "_" + fieldName.substr(0, maxFieldLength);
        int paddingNeeded = fixedLength - temp.length() - ext.length();

        if (destSize <= static_cast<size_t>(fixedLength) || paddingNeeded < 0) {
            throw std::runtime_error("Destination buffer too small or invalid filename length");
        }

        snprintf(dest, destSize, "%s%.*s%s", temp.c_str(), paddingNeeded, "____________", ext.c_str());
        dest[fixedLength] = '\0';
    }

    void computeFileNamesPerPeer(Peer* peer1, Peer* peer2) {
        if (!peer1 || !peer2) {
            throw std::invalid_argument("Peer pointers cannot be null");
        }

        std::string idStr1 = std::to_string(peer1->getPeerId());
        std::string idStr2 = std::to_string(peer2->getPeerId());

        // generate filenames for peer1
        formatFilename(peer1->publicRepo.ECPublicKeyfilename, sizeof(peer1->publicRepo.ECPublicKeyfilename), idStr1, "ecpubkey", ".pem");
        formatFilename(peer1->publicRepo.SymKeyfilename, sizeof(peer1->publicRepo.SymKeyfilename), idStr1, "symkeyElements", ".key");
        formatFilename(peer1->publicRepo.Transactionfilename, sizeof(peer1->publicRepo.Transactionfilename), idStr1, "transact", ".data");
        formatFilename(peer1->publicRepo.macECPublicKeyfilename, sizeof(peer1->publicRepo.macECPublicKeyfilename), idStr1, "macecpubkey", ".mac");

        formatFilename(peer1->privateRepo.ECPrivateKeyfilename, sizeof(peer1->privateRepo.ECPrivateKeyfilename), idStr1, "ecprivkey", ".pem");
        formatFilename(peer1->privateRepo.rsaPrivateKeyFilename, sizeof(peer1->privateRepo.rsaPrivateKeyFilename), idStr1, "rsaprivkey", ".prv");
        formatFilename(peer1->privateRepo.rsaPublicKeyFilename, sizeof(peer1->privateRepo.rsaPublicKeyFilename), idStr1, "rsapubkey", ".pub");
        formatFilename(peer1->privateRepo.peer_ECPublicKeyfilename, sizeof(peer1->privateRepo.peer_ECPublicKeyfilename), idStr2, "ecpubkey", ".pem");
        formatFilename(peer1->privateRepo.peer_macECPublicKeyfilename, sizeof(peer1->privateRepo.peer_macECPublicKeyfilename), idStr2, "macecpubkey", ".mac");

        // generate filenames for peer2
        formatFilename(peer2->publicRepo.ECPublicKeyfilename, sizeof(peer2->publicRepo.ECPublicKeyfilename), idStr2, "ecpubkey", ".pem");
        formatFilename(peer2->publicRepo.SymKeyfilename, sizeof(peer2->publicRepo.SymKeyfilename), idStr2, "symkeyElements", ".key");
        formatFilename(peer2->publicRepo.Transactionfilename, sizeof(peer2->publicRepo.Transactionfilename), idStr2, "transact", ".data");
        formatFilename(peer2->publicRepo.macECPublicKeyfilename, sizeof(peer2->publicRepo.macECPublicKeyfilename), idStr2, "macecpubkey", ".mac");

        formatFilename(peer2->privateRepo.ECPrivateKeyfilename, sizeof(peer2->privateRepo.ECPrivateKeyfilename), idStr2, "ecprivkey", ".pem");
        formatFilename(peer2->privateRepo.rsaPrivateKeyFilename, sizeof(peer2->privateRepo.rsaPrivateKeyFilename), idStr2, "rsaprivkey", ".prv");
        formatFilename(peer2->privateRepo.rsaPublicKeyFilename, sizeof(peer2->privateRepo.rsaPublicKeyFilename), idStr2, "rsapubkey", ".pub");
        formatFilename(peer2->privateRepo.peer_ECPublicKeyfilename, sizeof(peer2->privateRepo.peer_ECPublicKeyfilename), idStr1, "ecpubkey", ".pem");
        formatFilename(peer2->privateRepo.peer_macECPublicKeyfilename, sizeof(peer2->privateRepo.peer_macECPublicKeyfilename), idStr1, "macecpubkey", ".mac");

        // personal and peer transaction filenames
        formatFilename(peer1->personalTransactionFilename, sizeof(peer1->personalTransactionFilename), idStr1, "transact", ".data");
        formatFilename(peer1->peerTransactionFilename, sizeof(peer1->peerTransactionFilename), idStr2, "transact", ".data");

        formatFilename(peer2->personalTransactionFilename, sizeof(peer2->personalTransactionFilename), idStr2, "transact", ".data");
        formatFilename(peer2->peerTransactionFilename, sizeof(peer2->peerTransactionFilename), idStr1, "transact", ".data");
    }

    void parseInputFile(const std::string& filename, int& numPeers, std::map<std::string, int>& peerMap, std::vector<Transaction_struct>& transactions) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Unable to open file: " + filename);
        }

        std::string line;
        if (!std::getline(file, line)) {
            file.close();
            throw std::runtime_error("Empty file or missing peer count");
        }

        std::stringstream ss(line);
        if (!(ss >> numPeers) || numPeers <= 0) {
            file.close();
            throw std::runtime_error("Invalid number of peers: " + line);
        }

        while (std::getline(file, line)) {
            std::stringstream ss(line);
            int tId;
            std::string sender, receiver, subject, transData;
            int amount;
            char colon;

            // my format: tId:Sender:senderName Subject:subject receiverId:Receiver:receiverName TRANSACTION-DATA:amount
            if (!(ss >> tId >> colon) || colon != ':' ||
                !std::getline(ss, sender, ':') || sender != "Sender" ||
                !std::getline(ss, sender, ' ') || sender.empty() ||
                !std::getline(ss, subject, ':') || subject != "Subject" ||
                !std::getline(ss, subject, ' ') || subject.empty() ||
                !(ss >> tId >> colon) || colon != ':' || // receiverId
                !std::getline(ss, receiver, ':') || receiver != "Receiver" ||
                !std::getline(ss, receiver, ' ') || receiver.empty() ||
                !std::getline(ss, transData, ':') || transData != "TRANSACTION-DATA" ||
                !(ss >> amount)) {
                file.close();
                throw std::runtime_error("Invalid transaction format: " + line);
            }

            if (peerMap.find(sender) == peerMap.end()) {
                peerMap[sender] = generateRandomId();
            }
            if (peerMap.find(receiver) == peerMap.end()) {
                peerMap[receiver] = generateRandomId();
                while (peerMap[receiver] == peerMap[sender]) {
                    peerMap[receiver] = generateRandomId();
                }
            }

            transactions.push_back({
                peerMap[sender], sender, peerMap[receiver], receiver, subject, amount
                });
        }

        file.close();
    }
  
    void computeAllPeerPairFileNames(std::vector<std::unique_ptr<Peer>>& peers) {
        for (size_t i = 0; i < peers.size(); ++i) {
            for (size_t j = i + 1; j < peers.size(); ++j) {
                computeFileNamesPerPeer(peers[i].get(), peers[j].get());
            }
        }
    }

    std::vector<std::unique_ptr<Peer>> MockPeer(const std::map<std::string, int>& peerMap, const std::vector<Transaction_struct>& transactions) {
        std::vector<std::unique_ptr<Peer>> peers;
        std::map<int, Peer*> idToPeer;

        // create peers and initialize basic data
        for (const auto& [name, id] : peerMap) {
            auto peer = std::make_unique<Peer>();
            peer->setPeerId(id);
            peer->setName(name);

            std::string subject = "Subject_" + name;
            unsigned char* subjectCopy = new unsigned char[subject.length() + 1];
            std::memcpy(subjectCopy, subject.c_str(), subject.length() + 1);
            peer->setSubject(subjectCopy);

            idToPeer[id] = peer.get();
            peers.push_back(std::move(peer));
        }

        // compute filenames for all peer pairs
        computeAllPeerPairFileNames(peers);

        // assign transactions
        for (const auto& t : transactions) {
            if (idToPeer.find(t.senderId) != idToPeer.end()) {
                idToPeer[t.senderId]->addTransaction(t);
            }
            if (idToPeer.find(t.receiverId) != idToPeer.end()) {
                idToPeer[t.receiverId]->addTransaction(t);
            }
        }

        // set transactionData for each peer based on their transactions
        for (const auto& peer : peers) {
            std::stringstream ss;
            bool hasData = false;

            // collect sent transactions
            for (const auto& t : transactions) {
                if (t.senderId == peer->getPeerId()) {
                    if (!hasData) {
                        ss << "Sent: " << t.amount;
                        hasData = true;
                    }
                    else {
                        ss << ", Sent: " << t.amount;
                    }
                }
            }

            // collect received transactions
            for (const auto& t : transactions) {
                if (t.receiverId == peer->getPeerId()) {
                    if (!hasData) {
                        ss << "Received: " << t.amount;
                        hasData = true;
                    }
                    else {
                        ss << ", Received: " << t.amount;
                    }
                }
            }

            // set transactionData 
            if (hasData) {
                std::string data = ss.str();
                unsigned char* dataCopy = new unsigned char[data.length() + 1];
                std::memcpy(dataCopy, data.c_str(), data.length() + 1);
                peer->setTransactionData(dataCopy);
            }
        }

        return peers;
    }

    void PrintPeer(const Peer* peer) {
        if (!peer) {
            std::cout << "Peer is NULL\n";
            return;
        }
        peer->print();
    }

    void FreePeer(Peer* peer) {
        delete peer;
    }

    Peer* LoginPeerIntoSystem() {
        std::unique_ptr<Peer> peer = std::make_unique<Peer>();
        std::string input;

        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        int peerId;
        do {
            std::cout << "Enter Peer ID (positive integer): ";
            if (!std::getline(std::cin, input)) {
                throw std::runtime_error("Input stream error");
            }
            try {
                size_t pos;
                peerId = std::stoi(input, &pos);
                if (pos == input.length() && peerId >= 0) {
                    peer->setPeerId(peerId);
                    break;
                }
                std::cout << "Error: Peer ID must be a valid positive integer.\n";
            }
            catch (const std::exception&) {
                std::cout << "Error: Invalid input for Peer ID.\n";
            }
        } while (true);

        std::cout << "Enter Subject (max 100 chars, Enter to skip): ";
        if (std::getline(std::cin, input) && !input.empty()) {
            if (input.length() > 100) {
                input = input.substr(0, 100);
                std::cout << "Subject truncated to 100 characters.\n";
            }
            unsigned char* copy = new unsigned char[input.length() + 1];
            std::memcpy(copy, input.c_str(), input.length() + 1);
            peer->setSubject(copy);
        }

        std::cout << "Enter Transaction Data (max 10000 chars, Enter to skip): ";
        if (std::getline(std::cin, input) && !input.empty()) {
            if (input.length() > 10000) {
                input = input.substr(0, 10000);
                std::cout << "Transaction Data truncated to 10000 characters.\n";
            }
            unsigned char* copy = new unsigned char[input.length() + 1];
            std::memcpy(copy, input.c_str(), input.length() + 1);
            peer->setTransactionData(copy);
        }

        return peer.release();
    }

} 

