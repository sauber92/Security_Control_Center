#ifndef FIRMWARE_SERVER_H_INCLUDED
#define FIRMWARE_SERVER_H_INCLUDED

#include <stdio.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>

int generate_firmware_hash(char* digest);
int generate_firmware_signature(char* digest);
int sendData(BIO* sbio);
int firmware_server(BIO* sbio)

#endif