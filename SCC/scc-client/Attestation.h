#ifndef ATTESTATION_H_INCLUDED
#define ATTESTATION_H_INCLUDED

#include <stdio.h>
#include <string.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>
#include <tss/tss_error.h>

#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>

#define SIGN_KEY_UUID {0, 0, 0, 0, 0, {0, 0, 0, 5, 32}}
#define DBG(message, tResult) printf("(Line%d, %s) %s returned 0x%08x. %s.\n\n",__LINE__ ,__func__ , message, tResult, (char *)Trspi_Error_String(tResult));
#define DEBUG 1
#define BLOBLEN (1 << 10)

int generate_attestation_signature(char* extendValue);
int createAIK();
EVP_PKEY *load();
int sendData(BIO* sbio);
int receiveData(BIO* sbio, char* recvData);
int attestation_Daemon(BIO* sbio);

#endif
