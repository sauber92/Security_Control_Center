#include "common.h"
#include <stdio.h>
#include "sslthread.h"


void handle_error(const char *file, int lineno, const char *msg)
{
	fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
	ERR_print_errors_fp(stderr);
	exit(-1);
}

void init_OpenSSL()
{
	if (!THREAD_setup() || !SSL_library_init())
	{
		fprintf(stderr, "** OpenSSL initialization failed!\n");

		system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
				insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"** OpenSSL initialization failed!\", 2)\
				'");

		exit(-1);
	}
	SSL_load_error_strings();
}


	
