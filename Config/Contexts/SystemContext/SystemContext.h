#pragma once
#include "Peer.h"
#include <random>
#include <string>
#include <vector>
#include <map>
#include <memory>

namespace SystemContext {

        void exchangeFilenameInfos(Peer* sender, Peer* receiver);
        int generateRandomId();
        void formatFilename(char* dest, size_t destSize, const std::string& idStr, const std::string& fieldName, const std::string& ext);
        void computeFileNamesPerPeer(Peer* peer1, Peer* peer2);
        void parseInputFile(const std::string& filename, int& numPeers, std::map<std::string, int>& peerMap, std::vector<Transaction_struct>& transactions);
        std::vector<std::unique_ptr<Peer>> MockPeer(const std::map<std::string, int>& peerMap, const std::vector<Transaction_struct>& transactions);
        void PrintPeer(const Peer* peer);
        void FreePeer(Peer* peer);
        Peer* LoginPeerIntoSystem();
} 