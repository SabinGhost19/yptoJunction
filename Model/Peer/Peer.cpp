#pragma once
#include "Peer.h"
#include <iostream>
#include <cstring>

Peer::Peer() {
    std::memset(personalTransactionFilename, 0, sizeof(personalTransactionFilename));
    std::memset(peerTransactionFilename, 0, sizeof(peerTransactionFilename));
    std::memset(&publicRepo, 0, sizeof(publicRepo));
    std::memset(&privateRepo, 0, sizeof(privateRepo));
}

void Peer::setSubject(unsigned char* subj) {
    if (!subj) {
        subject.reset();
        return;
    }
    size_t len = std::strlen(reinterpret_cast<char*>(subj)) + 1;
    subject = std::make_unique<unsigned char[]>(len);
    std::memcpy(subject.get(), subj, len);
}

void Peer::setTransactionData(unsigned char* data) {
    if (!data) {
        transactionData.reset();
        return;
    }
    size_t len = std::strlen(reinterpret_cast<char*>(data)) + 1;
    transactionData = std::make_unique<unsigned char[]>(len);
    std::memcpy(transactionData.get(), data, len);
}

void Peer::print() const {
    std::cout << "Peer ID: " << peerId << "\n"
        << "Name: " << (name.empty() ? "None" : name) << "\n"
        << "Comm Peer ID: " << commPeerId << "\n"
        << "Subject: " << (subject ? reinterpret_cast<const char*>(subject.get()) : "None") << "\n"
        << "Transaction Data: " << (transactionData ? reinterpret_cast<const char*>(transactionData.get()) : "None") << "\n"
        << "Transactions:\n";
    if (transactions.empty()) {
        std::cout << "  None\n";
    }
    else {
        for (const auto& t : transactions) {
            std::cout << "  From " << t.senderName << " (ID: " << t.senderId << ") to "
                << t.receiverName << " (ID: " << t.receiverId << "), Subject: "
                << t.subject << ", Amount: " << t.amount << "\n";
        }
    }
}