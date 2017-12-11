#ifndef FIRMWARE_SERVER_H_INCLUDED
#define FIRMWARE_SERVER_H_INCLUDED

#include <stdio.h>

#include <openssl/bio.h>
int sendData(BIO* sbio);
int firmware_server(BIO* sbio);

#endif
