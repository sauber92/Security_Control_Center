#ifndef SECURE_FIRMWARE_UPDATE_H_INCLUDED
#define SECURE_FIRMWARE_UPDATE_H_INCLUDED

#include <stdio.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>

#define SIGN_KEY_UUID {0, 0, 0, 0, 0, {0, 0, 0, 5, 32}}
#define DBG(message, tResult) printf("(Line%d, %s) %s returned 0x%08x. %s.\n\n",__LINE__ ,__func__ , message, tResult, (char *)Trspi_Error_String(tResult));
#define DEBUG 1

int generate_Signature();
int verify_firmware_version_Signature();
int receive_firmware(BIO *sbio);
int Update_Daemon(BIO* sbio);
int receiveData(BIO* sbio, char* recvData);

#endif
