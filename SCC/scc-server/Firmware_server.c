#include "Firmware_server.h"

int sendData(BIO* sbio)
{
	int len;
	FILE* fp = NULL;
	char* buf = NULL;
	char* buf2 = NULL;
	char tmpbuf[1024];

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
	buf2 = (char*)calloc(len, sizeof(char));

	fread(buf2, 1, len, fp);
	BIO_write(sbio, buf2, len);
	fclose(fp);
	free(buf2);

	return 0;
}

int firmware_server(BIO* sbio)
{
	int res = 0;
	while(1){
		res = sendData(sbio);
		if(res==0)
			break;
		else {
			printf("Error occur\n");
			break;
		}
	}

	return 0;
}

