#include "Attestation_server.h"

int attestation_server_hash(unsigned char* xor_result)
{
    FILE *fp; // File Pointer
    int i; // for value
    unsigned char digest[SHA_DIGEST_LENGTH]; // SHA256 result temp save value
    unsigned char buf[1024]; // File read data buffer
    SHA_CTX ctx; // SHA256 Context

    /// u-boot.bin hash ///
    if(!(fp = fopen("/boot/u-boot.bin", "rb"))) {
        printf("File open error\n");
        return 1;
    }

    SHA1_Init(&ctx);
    while((i = fread(buf, 1, sizeof(buf), fp)) > 0) {
        SHA1_Update(&ctx, buf, i);
    }
    SHA1_Final(digest, &ctx);
    fclose(fp);

    /// image.fit hash ///
    if(!(fp = fopen("/boot/image.fit", "rb"))) {
        printf("File open error\n");
        return 1;
    }

    SHA1_Init(&ctx);
    while((i = fread(buf, 1, sizeof(buf), fp)) > 0) {
        SHA1_Update(&ctx, buf, i);
    }
    SHA1_Final(xor_result, &ctx);
    fclose(fp);

    /// u-boot hash xor image hash ///
    for(i=0; i<20; i++)
        xor_result[i] = xor_result[i]^digest[i];

    /// RaspberryPi Serial number hash ///
    if(!(fp = fopen("Secure_boot_daemon", "rb"))) {
        printf("File open error\n");
        return 1;
    }

    SHA1_Init(&ctx);
    while((i = fread(buf, 1, sizeof(buf), fp)) > 0) {
        SHA1_Update(&ctx, buf, i);
    }
    SHA1_Final(digest, &ctx);
    fclose(fp);

    /// (u-boot hash xor image hash) xor serial hash ///
    for(i=0; i<20; i++)
        xor_result[i] = xor_result[i]^digest[i];

	    /// RaspberryPi Serial number hash ///
    if(!(fp = fopen("firmware", "rb"))) {
        printf("File open error\n");
        return 1;
    }

    SHA1_Init(&ctx);
    while((i = fread(buf, 1, sizeof(buf), fp)) > 0) {
        SHA1_Update(&ctx, buf, i);
    }
    SHA1_Final(digest, &ctx);
    fclose(fp);

    /// (u-boot hash xor image hash) xor serial hash ///
    for(i=0; i<20; i++)
        xor_result[i] = xor_result[i]^digest[i];

    return 0;
}

int receiveData(BIO* sbio)
{
	FILE* fp;
	int len;
	char tmpbuf[256];

	fp = fopen("Signature", "wb");
	len = BIO_read(sbio, tmpbuf, 256);
	fwrite(tmpbuf, 1, len, fp);
	fclose(fp);

	return 0;
}

int decrypt_signature(unsigned char* xor_result)
{
	FILE *fp = NULL;
	char sign[256];
	char decrypt_sign[20];
	int sign_len = 0;

	if(!(fp=fopen("Signature", "rb")))
	{
		printf("File open error\n");
		return 1;
	}
    fread(sign_b, 1, 256, fp);
    fclose(fp);

	sign_len = RSA_public_decrypt(256, sign_b, decrypt_sign, rsa, padding);
	if(sign_len < 0)
	{
		printf("Signature decryption failed\n");
		return 1;
	}

	if(strncmp(xor_result, decrypt_sign, 20) != 0)
		return 1;

	return 0;
}

int attestation_server(BIO* sbio)
{
	unsigned char xor_result[20];

	if(attestation_server_hash(xor_result)!=0)
	{
		printf("Attestation_server_hash falied\n");
		return 1;
	}

	receiveData(sbio);

	if(decrypt_signature(xor_result)!=0)
	{
		printf("Signature decryption failed\n");
		return 1;
	}

	return 0;
}
