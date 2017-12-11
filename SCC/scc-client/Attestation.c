#include "Attestation.h"

int generate_attestation_signature(char* extendValue)
{
    TSS_HPCRS hPcrs;
    TSS_HTPM hTpm;
    TSS_HCONTEXT hContext;
    TSS_RESULT result;
    TSS_HKEY hSRK;
    TSS_HPOLICY hSRKPolicy;
    TSS_PCR_EVENT *prgPcrEvents, *extendEvents;
    TSS_HHASH hHash;
    BYTE hash_value[20], *f_data;
    UINT32 PCR_length, number = 23;

    FILE* fp;
    int i;
    SHA_CTX ctx;
    unsigned char digest[SHA_DIGEST_LENGTH];
    unsigned char buf[1024];

    result = Tspi_Context_Create(&hContext);
#if DEBUG
    DBG("Context Create\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Context Create\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_Connect(hContext, NULL);
#if DEBUG
    DBG("Context Connect\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Context Connect\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_GetTpmObject(hContext, &hTpm);
    DBG("Get Tpm Object\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Get Tpm Object\", 1)\
			'");

    if(!(fp = fopen("/boot/u-boot.bin", "rb")))
    {
        printf("File open failed\n");
        return 1;
    }

    SHA1_Init(&ctx);
    while((i = fread(buf, 1, sizeof(buf), fp)) > 0)
        SHA1_Update(&ctx, buf, i);
    SHA1_Final(digest, &ctx);
    fclose(fp);

    result = Tspi_TPM_PcrExtend(hTpm, 16, 20, (BYTE *)digest, NULL, &PCR_length, &f_data);
#if DEBUG
    DBG("PCR_Extend\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"PCR_Extend\", 1)\
			'");
#endif
    if(result!=0) return 1;

    if(!(fp = fopen("/boot/image.fit", "rb")))
    {
        printf("File open failed\n");
        return 1;
    }

    SHA1_Init(&ctx);
    while((i = fread(buf, 1, sizeof(buf), fp)) > 0)
        SHA1_Update(&ctx, buf, i);
    SHA1_Final(digest, &ctx);
    fclose(fp);

    result = Tspi_TPM_PcrExtend(hTpm, 16, 20, (BYTE *)digest, NULL, &PCR_length, &f_data);
#if DEBUG
    DBG("PCR_Extend\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"PCR_Extend\", 1)\
			'");
#endif
    if(result!=0) return 1;

    if(!(fp = fopen("firmware", "rb")))
    {
        printf("File open error\n");
        return 1;
    }

    SHA1_Init(&ctx);
    while((i = fread(buf, 1, sizeof(buf), fp)) > 0)
        SHA1_Update(&ctx, buf, i);
    SHA1_Final(digest, &ctx);
    fclose(fp);

    result = Tspi_TPM_PcrExtend(hTpm, 16, 20, (BYTE *)digest, NULL, &PCR_length, &f_data);
#if DEBUG
    DBG("PCR_Extend\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"PCR_Extend\", 1)\
			'");
#endif
    if(result!=0) return 1;

    memcpy(extendValue, f_data, 20);

    result = Tspi_Context_FreeMemory(hContext, NULL);
#if DEBUG
    DBG("Free Memory\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Free Memory\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_Close(hContext);
#if DEBUG
    DBG("Close TPM\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Close TPM\", 1)\
			'");
#endif
    if(result!=0) return 1;

    return 0;
}

int createAIK()
{
    TSS_HTPM hTPM;
    TSS_HCONTEXT hContext;
    TSS_RESULT result;
    TSS_HKEY hSRK;
    TSS_HPOLICY hSRKPolicy, hTPMPolicy;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    TSS_HKEY hPCA;
    int initFlags = TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048;
    TSS_HKEY hAIK;
    BYTE *lab, *blob, derBlob[BLOBLEN];
    UINT32 blobLen, derBlobLen;
    FILE* out = NULL;
    BIO *outb = NULL;
    unsigned char *blob_asn1 = NULL;
    int asn1_len;
    ASN1_OCTET_STRING *blob_str = NULL;
    
    result = Tspi_Context_Create(&hContext);
#if DEBUG
    DBG("Context Create\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Context Create\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_Connect(hContext, NULL);
#if DEBUG
    DBG("Context Connect\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Context Connect\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
#if DEBUG
    DBG("Get SRK handle\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Get SRK handle\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
#if DEBUG
    DBG("Get Policy\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Get Policy\", 1)\
			'");
#endif
    if(result!=0) return 1;

    //result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 10, SRK_PASSWD);
    result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
#if DEBUG
    DBG("Set Secret\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Set Secret\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
#if DEBUG
    DBG("Get TPM Object\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Get TPM Object\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hTPMPolicy);
#if DEBUG
    DBG("Create Context\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Create Context\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Policy_AssignToObject(hTPMPolicy, hTPM);
#if DEBUG
    DBG("Policy Assign\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Policy Assign\", 1)\
			'");
#endif
    if(result!=0) return 1;

    //result = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_PLAIN, 10, SRK_PASSWD);
    result = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
#if DEBUG
    DBG("Set Secret\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Set Secret\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, TSS_KEY_TYPE_LEGACY | TSS_KEY_SIZE_2048, &hPCA);
#if DEBUG
    DBG("Create PCA\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Create PCA\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Key_CreateKey(hPCA, hSRK, 0);
#if DEBUG
    DBG("Create Key\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Create Key\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hAIK);
#if DEBUG
    DBG("Create AIK Object\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Create AIK Object\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_TPM_CollateIdentityRequest(hTPM, hSRK, hPCA, 0, lab, hAIK, TSS_ALG_AES, &blobLen, &blob);
#if DEBUG
    DBG("Create AIK\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Create AIK\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB, &blobLen, &blob);
#if DEBUG
    DBG("Get Attribute\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Get Attribute\", 1)\
			'");
#endif
    if(result!=0) return 1;

    outb = BIO_new_file("AIK", "wb");
    blob_str = ASN1_OCTET_STRING_new();
    ASN1_STRING_set(blob_str, blob, blobLen);
    asn1_len = i2d_ASN1_OCTET_STRING(blob_str, &blob_asn1);
    PEM_write_bio(outb, "TSS KEY BLOB", "", blob_asn1, asn1_len);
    BIO_free(outb);

    result = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, &blobLen, &blob);
#if DEBUG
    DBG("Get Attribute\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Get Attribute\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_EncodeDER_TssBlob(blobLen, blob, TSS_BLOB_TYPE_PUBKEY, &derBlobLen, derBlob);
#if DEBUG
    DBG("Encode\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Encode\", 1)\
			'");
#endif
    if(result!=0) return 1;

    derBlobLen = sizeof(derBlob);

    result = Tspi_EncodeDER_TssBlob(blobLen, blob, TSS_BLOB_TYPE_PUBKEY, &derBlobLen, derBlob);
#if DEBUG
    DBG("Encode\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Encode\", 1)\
			'");
#endif
    if(result!=0) return 1;

    if(!(out = fopen("AIK_public", "wb")))
    {
        printf("File open error\n");
        return 1;
    }
    fwrite(derBlob, 1, derBlobLen, out);
    fclose(out);
   
    result = Tspi_Context_FreeMemory(hContext, blob);
#if DEBUG
    DBG("Free Memory\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Free Memory\", 1)\
			'");
#endif
    if(result!=0) return 1;

    return 0;
}
int sendData(BIO* sbio)
{
	int len;
	FILE* fp = NULL;
	char* buf = NULL;

	if(!(fp=fopen("AIK_public", "rb")))
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

int attestation_Daemon(BIO* sbio)
{
	int result;
	char extendValue[20];
	unsigned char encrypted[256];
	FILE* fp = NULL;
	char* sendbuf = NULL;
	char recvbuf[10];

	if(generate_attestation_signature(extendValue)==0)
	{
		printf("Attestation_Signature generation failed\n");
		system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"Attestation_Signature generation failed\", 2)\
			'");

		return 1;
	}

	if(createAIK()==0)
	{
		printf("AIK Creation failed\n");
		system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into remote_attestation (`id`, `attestation_log`, `attestation_parity`) values(1001, \"AIK Creation failed\", 2)\
			'");

		return 1;
	}

	sendData(sbio);

    return 0;
}
