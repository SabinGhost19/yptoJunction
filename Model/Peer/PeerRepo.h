#pragma once
typedef struct publicRepoFileStructure {
    char ECPublicKeyfilename[68];
    char SymKeyfilename[68];
    char Transactionfilename[68];
    char macECPublicKeyfilename[68];
}publicRepoFileStructure;


typedef struct privateRepoFileStructure {
    char ECPrivateKeyfilename[68];
    char rsaPrivateKeyFilename[68];
    char rsaPublicKeyFilename[68];
    char peer_ECPublicKeyfilename[68];
    char peer_macECPublicKeyfilename[68];
    unsigned char* sharedSecret;
}privateRepoFileStructure;
