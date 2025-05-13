#pragma once
#include "PubKeyMac.h"
#include"PubKeyMacRepository.h"
#include"Logger.h"

#ifdef __cplusplus
extern "C" {
#endif

    class GMCController {
    private:
        PubKeyMacRepository* pubkeymacRepository = NULL;
        Logger* logger = nullptr;
        std::string peerName;
    public:
        GMCController(PubKeyMacRepository* pubkeymacRepository,std::string peerName);
        void generate_EC_key_pairs();
        int validate_public_key(const char* macFilename, EC_KEY* pubKey);
        long get_time_diff();
        unsigned char* generate_gcm_tag(unsigned char* data, long data_len, const unsigned char* key);
        unsigned char* generate_pbkdf2_key(long time_data);
        std::string getPeerName();
    };

#ifdef __cplusplus
}
#endif