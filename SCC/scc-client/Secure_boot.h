#ifndef SECURE_BOOT_H_INCLUDED
#define SECURE_BOOT_H_INCLUDED

#include <stdio.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <tss/tss_error.h>
#include <trousers/trousers.h>

#include <openssl/sha.h>
#include <openssl/bio.h>

#define SIGN_KEY_UUID {0, 0, 0, 0, 0, {0, 0, 0, 5, 32}}
#define DBG(message, tResult) printf("(Line%d, %s) %s returned 0x%08x. %s.\n\n",__LINE__ ,__func__ , message, tResult, (char *)Trspi_Error_String(tResult));
#define DEBUG 1

char get_plain(unsigned char ch);
void createSRK(unsigned char* SRK_PASSWD, unsigned char* xor_result);
int secure_boot_hash(unsigned char* xor_result);
int verify_Bootloader_Signature();
int changeSRKPW(unsigned char* SRK_PASSWD);

#endif
