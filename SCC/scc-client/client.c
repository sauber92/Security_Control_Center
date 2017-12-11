#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "Secure_boot.h"
#include "Secure_Firmware_Update.h"
#include "Attestation.h"
#include "sslthread.h"

void msg_out_error(char *msg)
{
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}

void SecureBoot()
{
//	Secure_Boot_Daemon();
}

void SecureUpdate(BIO* sbio)
{
	char recvbuf[1024];

    printf("Secure Update start\n");

	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Secure Update start\", 1)\
			'");

	Update_Daemon(sbio);
}

void Attestation(void *data)
{
	char recvbuf[10];
	BIO* sbio = (BIO *)data;
	while(1)
	{
		BIO_read(sbio, recvbuf, 10);
		if(strcmp(recvbuf, "ATTstart")==0){}
//			attestation_Daemon(sbio);
	}
}

int main (int argc, char *argv[])
{
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	
	BIO *sbio, *out;
    BIO *bio_err = 0;
    int res;
    SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *ssl;
	pthread_t p_thread[3];
	int thr_id;
	int status;
    THREAD_TYPE tid;

	init_OpenSSL();
	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    meth = SSLv23_client_method();
    ctx = SSL_CTX_new(meth);
    sbio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(sbio, &ssl);

    if(!ssl)
    {
        fprintf(stderr, "Can't locate SSL pointer\n");

		system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
				insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Cannot locate SSL pointer\", 2)\
				'");

        exit(1);
    }
    
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(sbio, "163.180.118.193:5000");
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    res = BIO_do_connect(sbio);
    if(res <= 0)
    {
        fprintf(stderr, "Error establishing SSL connection\n");
        ERR_print_errors_fp(stderr);

		system("mysql -h '163.180.118.193 -uroot -'proot' scc --ssl -e '\
				insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Error establishing SSL connection\", 2)\
				'");

        exit(1);
    }

	fprintf(stderr, "Connection opened\n");

	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Connection opened\", 1)\
			'");

	//THREAD_CREATE(tid, SecureUpdate, sbio);
    Secure_Boot_Daemon(sbio);
    attestation_Daemon(sbio);
    SecureUpdate(sbio);
    fprintf(stderr, "Connection Closed\n");

	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Connection Closed\", 1)\
			'");

    BIO_free_all(sbio);
	BIO_free(out);

	return 0;
}

