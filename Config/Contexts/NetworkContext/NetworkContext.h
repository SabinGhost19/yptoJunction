#pragma once
#include <iostream>
#include <string>
#include <cstring>
#include <limits>
#include"Peer.h"
#include"GMCController.h"
#include"ECDHController.h"
#include"SymKeyController.h"
#include"AES_OFBController.h"
#include"RSASignController.h"

namespace NetworkContext {
    void simulateCommunicationINIT(Peer* sender, Peer* listener);
    GMCController* __simulateECDHKeyGen_(Peer* peer);
    void __simulateECDHGenExchange_perPeer(Peer* peer, GMCController* gmcController);
    void __simulateSymKeyGen(Peer* peer);
    unsigned char* simulateENCRYPTION_AES_FANCY_OFB(Peer* peer);
    unsigned char* SimulateTransactionSign(Peer* peer, unsigned char* bufferToBeSigned, long bufferToBeSigned_len, long* signed_transaction_len);
    void simulateFinishingDataAndSendingIt();
}
