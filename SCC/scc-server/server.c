#include <stdio.h>
#include <pthread.h>
#include <assert.h>

#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#include "sslthread.h"
#include "Firmware_server.h"
#include "Attestation_server.h"

#define THREAD_CC *
#define THREAD_TYPE pthread_t
#define THREAD_CREATE(tid, entry, arg) pthread_create(&(tid), NULL, (entry), (arg))

#define PORT "5000"

#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

void handle_error(const char *file, int lineno, const char *msg)
{
	fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
	ERR_print_errors_fp(stderr);
	exit(-1);
}

void init_OpenSSL()
{
	if(!THREAD_setup() || !SSL_library_init())
	{
		fprintf(stderr, "** OpenSSL initiallization failed\n");
		exit(-1);
	}
	SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
}

void do_server_loop(BIO *sbio)
{
	int len;
	char buf[1024];
	
	//while(1)
	//{
		printf("do_server_loop\n");
		len = BIO_read(sbio, buf, 1024);

    //JJY
    printf("%s\n", buf);

		if(strcmp(buf, "Update")==0) {
			printf("Secure_firmware_update start\n");
			firmware_server(sbio);
		}
		else if(strcmp(buf, "Attest")==0)
			attestation_server(sbio);
	//}
}

void THREAD_CC server_thread(void* arg)
{
	BIO* client = (BIO *)arg;

	fprintf(stderr, "Connection opened\n");
	do_server_loop(client);
	fprintf(stderr, "Connection closed\n");

	BIO_free(client);
	ERR_remove_state(0);
}

int main(void)
{
  BIO *bio, *abio, *out;
	BIO *bio_err = 0;
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	THREAD_TYPE tid;
	int res;
	FILE* fp = NULL;
	int len;
	char *buf = "";

	init_OpenSSL();

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);
	res = SSL_CTX_use_certificate_chain_file(ctx, "cert");
	assert(res);

	res = SSL_CTX_use_PrivateKey_file(ctx, "private", SSL_FILETYPE_PEM);
	assert(res);

	res = SSL_CTX_check_private_key(ctx);
	assert(res);

	bio = BIO_new_ssl(ctx, 0);
	BIO_get_ssl(bio, &ssl);
	assert(ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	abio = BIO_new_accept("5000");

	BIO_set_accept_bios(abio, bio);

	if(BIO_do_accept(abio) <= 0) {
		fprintf(stderr, "Error setting up accept BIO\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if(BIO_do_accept(abio) <= 0) {
		fprintf(stderr, "Error in connection\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	out = BIO_pop(abio);
	BIO_free_all(abio);

	if(BIO_do_handshake(out) <= 0) {
		fprintf(stderr, "Error in SSL handshake\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	firmware_server(out);
	attestation_server(out);
	
	BIO_flush(out);
	BIO_free_all(out);

  SSL_CTX_free(ctx);

	return 0;
}
