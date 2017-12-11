#include "Firmware_server.h"

int generate_firmware_hash(char* digest)
{
	FILE* fp = NULL;
	int fileSize;
	char* tmpbuf = NULL;
	SHA_CTX sha1;

	if(!(fp=fopen("firmware", "rb")))
	{
		printf("File open error\n");
		return 1;
	}

	fseek(fp, 0, SEEK_END);
	fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	tmpbuf = malloc(size+1);

	fread(tmpbuf, 1, fileSize, fp);
	fclose(fp);

	SHA1_Init(&sha1);
	SHA1_Update(&sha1, tmpbuf, fileSize);
	SHA1_Final(digest, &sha1);

	free(tmpbuf);

	return 0;
}

int generate_firmware_signature(char* digest)
{
	FILE* fp = NULL;
	RSA* priv_key = NULL;
	int sign_len;
	char sign[256];

	if(!(fp=fopen("private", "rb")))
	{
		printf("File open error\n");
		return 1;
	}

	priv_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	if(priv_key==NULL)
	{
		printf("Read Private Key for RSA Error\n");
		return 1;
	}

	sign_len = RSA_private_encrypt(20, digest, sign, priv_key, RSA_PKCS1_PADDING);
	if(sign_len < 1)
		printf("RSA private encryption failed\n");

	fclose(fp);

	if(!(fp=fopen("Signature", "wb")))
	{
		printf("File open error\n");
		return 1;
	}
	fwrite(sign, 1, 256, fp);
	fclose(fp);

	return 0;
}

int sendData(BIO* sbio)
{
	int len;
	FILE* fp = NULL;
	char* buf = NULL;

	if(!(fp=fopen("firmware", "rb")))
	{
		printf("File open error\n");
		return 1;
	}
	fseek(fp, 0L, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	buf = (char*)calloc(len, sizeof(char));

	fread(buf, 1, len, fp);
	BIO_write(sbio, buf, len);
	fclose(fp);
	free(buf);

	if(!(fp=fopen("Signature", "rb")))
	{
		printf("File open error\n");
		return 1;
	}
	fseek(fp, 0L, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	buf = (char*)calloc(len, sizeof(char));

	fread(buf, 1, len, fp);
	BIO_write(sbio, buf, len);
	fclose(fp);
	free(buf);

	return 0;
}

//int firmware_server(BIO* sbio)
int main(void)
{
	char digest[20];

	if(generate_firmware_hash(digest)!=0)
	{
		printf("Firmware hash generation failed\n");
		return 1;
	}

	if(generate_firmware_signature(digest)!=0)
	{
		printf("Firmware signature generation failed\n");
		return 1;
	}

	sendData(sbio);

	return 0;
}
