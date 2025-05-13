#pragma once
#include <string>
#include <vector>
#include <memory>
#include "PeerRepo.h"

struct Transaction_struct {
    int senderId;
    std::string senderName;
    int receiverId;
    std::string receiverName;
    std::string subject;
    int amount;
};

class Peer {
private:
    bool listening = false;
    bool sending = false;
    std::unique_ptr<unsigned char[]> transactionData;
    std::unique_ptr<unsigned char[]> subject;
    int peerId = 0;
    int commPeerId = 0;
    std::vector<Transaction_struct> transactions;

public:
    std::string name;
    char personalTransactionFilename[120];
    char peerTransactionFilename[120];
    publicRepoFileStructure publicRepo;
    privateRepoFileStructure privateRepo;

    Peer();
    ~Peer() = default;

    int getCommPeerId() const { return commPeerId; }
    int getPeerId() const { return peerId; }
    const unsigned char* getSubject() const { return subject.get(); }
    const unsigned char* getTransactionData() const { return transactionData.get(); }

    void addTransaction(const Transaction_struct& t) { transactions.push_back(t); }
    void setStateListener() { listening = true; sending = false; }
    void setStateSender() { sending = true; listening = false; }
    void setSubject(unsigned char* subj);
    void setPeerId(int id) { peerId = id; }
    void setCommPeerId(int id) { commPeerId = id; }
    void setName(const std::string& n) { name = n; }
    void setTransactionData(unsigned char* data);
    void print() const;
};