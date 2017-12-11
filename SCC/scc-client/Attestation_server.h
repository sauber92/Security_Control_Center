#ifndef ATTESTATION_SERVER_H_INCLUDED
#define ATTESTATION_SERVER_H_INCLUDED

#include <stdio.h>

#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>

int attestation_server_hash(unsigned char* xor_result);
int receiveData(BIO* sbio);
int decrypt_signature(unsigned char* xor_result);
int attestation_server(BIO* sbio);

#endif

