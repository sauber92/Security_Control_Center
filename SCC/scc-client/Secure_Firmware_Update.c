#include "Secure_Firmware_Update.h"

int generate_Signature()
{
    TSS_HCONTEXT hContext;
    TSS_RESULT result;
    TSS_HKEY hSRK;
    TSS_HPOLICY hSRKPolicy, hNVPolicy;
    TSS_UUID MY_UUID = SIGN_KEY_UUID;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    TSS_HKEY hSigning_key;
    TSS_FLAG initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
    TSS_HHASH hHash;
    TSS_HNVSTORE hNVStore;
    BYTE *pubkey, *sig;
    UINT32 pubKeySize, srk_authusage, sigLen;
     FILE* f = NULL;
     SHA_CTX sha1;
     char str[SHA_DIGEST_LENGTH];
     char buf[1024];
    int i;

     if(!(f = fopen("Signature", "rt"))) {
         printf("open error\n");
         return(1);
     }
 
     SHA1_Init(&sha1);
     while((i = fread(buf, 1, sizeof(buf), f)) > 0 )
         SHA1_Update(&sha1, buf, i);
 
     SHA1_Final(str, &sha1);
     fclose(f);

    result = Tspi_Context_Create(&hContext);
#if DEBUG
    DBG("Create a context\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Create a context\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_Connect(hContext, NULL);
#if DEBUG
    DBG("Connect to TPM\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Connect to TPM\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hSigning_key);
#if DEBUG
    DBG("Create the key object\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Create the key object\", 1)\
			'");
#endif
    if(result!=0) return 1;

         result = Tspi_SetAttribUint32(hSigning_key, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_SIGSCHEME, TSS_SS_RSASSAPKCS1V15_SHA1);
             #if DEBUG
                 DBG("Set the key's padding type\n", result);
			     system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			     insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Set the key padding type\", 1)\
				 '");
             #endif
                 if(result!=0) return 1;

    result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
#if DEBUG
    DBG("Get SRK handle\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Get SRK handle\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_GetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, &srk_authusage);
#if DEBUG
    DBG("Get Attribute\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Get Attribute\", 1)\
			'");
#endif
    if(result!=0) return 1;

//    if(srk_authusage)
  //  {
        result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
#if DEBUG
        DBG("Tspi_GetPolicyObject\n", result);
		system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Tspi_GetPolicyObject\", 1)\
			'");
#endif
        if(result!=0) return 1;

//        result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 10, SRK_PASSWD);
        result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
#if DEBUG
        DBG("Set Secret\n", result);
		system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Set Secret\", 1)\
			'");
#endif
        if(result!=0) return 1;
   // }
  result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hSigning_key); // Create RSA Key(Singing
   #if DEBUG
        DBG("Create RSA Object\n", result);
		system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Create RSA Object\", 1)\
			'");
   #endif
       if(result!=0) return 1;
  
       result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, MY_UUID, &hSigning_key); // Load Signing key(Signing ke
  #if DEBUG
        DBG("Load Signing key\n", result);
		system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Load Signing key\", 1)\
			'");
   #endif
       if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hHash);
#if DEBUG
    DBG("Create Object\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Create Object\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Hash_SetHashValue(hHash, 20, str);
#if DEBUG
    DBG("Set Hash\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Set Hash\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Hash_Sign(hHash, hSigning_key, &sigLen, &sig);
#if DEBUG
    DBG("Hash Sign\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Hash Sign\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0, &hNVStore);
#if DEBUG
    DBG("Create NV object\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Create NV object\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0, 0x00011109);
#if DEBUG
    DBG("Set index\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Set index\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_PERMISSIONS, 0, TPM_NV_PER_OWNERWRITE);
#if DEBUG
    DBG("Set Policy\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Set Policy\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_DATASIZE, 0, 0x100);
#if DEBUG
    DBG("Set size\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Set size\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hNVPolicy);
#if DEBUG
    DBG("Create Context\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Create Context\", 1)\
			'");
#endif
    if(result!=0) return 1;
     result = Tspi_Policy_SetSecret(hNVPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
 #if DEBUG
    DBG("TPM SetSecret\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"TPM SetSecret\", 1)\
			'");
 #endif
    if(result!=0) return 1;

    result = Tspi_Policy_AssignToObject(hNVPolicy, hNVStore);
#if DEBUG
    DBG("Policy Assign\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Policy Assign\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_FreeMemory(hContext, NULL);
#if DEBUG
    DBG("Free Memory\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Free Memory\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_Close(hContext);
#if DEBUG
    DBG("Close TPM\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Close TPM\", 1)\
			'");
#endif
    if(result!=0) return 1;

    return 0;
}

int verify_firmware_version_Signature()
{
    TSS_HCONTEXT hContext;
    TSS_RESULT result;
    TSS_HKEY hSRK;
    TSS_HPOLICY hSRKPolicy, hNVPolicy;
    TSS_UUID MY_UUID = SIGN_KEY_UUID;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    TSS_HKEY hSigning_key;
    TSS_FLAG initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
    TSS_HHASH hHash;
    TSS_HNVSTORE hNVStore;
    BYTE *pubkey, *sig, *data;
    UINT32 pubKeySize = 256, srk_authusage, sigLen, datasize = 256;
    FILE* f = NULL;
    SHA_CTX sha1;
    char str[SHA_DIGEST_LENGTH];
    char buf[1024];
    int i;
    if(!(f = fopen("Signature", "rb"))) {
        return(1);
    }

    SHA1_Init(&sha1);
    while((i = fread(buf, 1, sizeof(buf), f)) > 0 )
        SHA1_Update(&sha1, buf, i);

    SHA1_Final(str, &sha1);
    fclose(f);

    result = Tspi_Context_Create(&hContext);
#if DEBUG
    DBG("Create a Context\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Create a Context\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_Connect(hContext, NULL);
#if DEBUG
    DBG("Connect to TPM\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Connect to TPM\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0, &hNVStore);
#if DEBUG
    DBG("Create NV Object\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Create NV Object\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result =  Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0, 0x00011106);
#if DEBUG
    DBG("Set index\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Set index\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_PERMISSIONS, 0, TPM_NV_PER_OWNERWRITE); //TPM NVRAM value config
#if DEBUG
    DBG("Set NVRAM policy\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Set NVRAM policy\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_DATASIZE, 0, 0x100);
#if DEBUG
    DBG("Set Size\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Set Size\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_NV_ReadValue(hNVStore, 0, &datasize, &data);
#if DEBUG
    DBG("Read value\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Read value\", 1)\
			'");
#endif
    if(result!=0) return 1;

    if(data==NULL)
    {
        printf("NVRAM read failed\n");
		system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"NVRAM read failed\", 2)\
			'");

        return 1;
    }

    result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
#if DEBUG
    DBG("Get SRK handle\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Get SRK handle\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_GetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, &srk_authusage);
#if DEBUG
    DBG("Get Attribute\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Get Attribute\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
#if DEBUG
    DBG("Set Secret\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Set Secret\", 1)\
			'");
#endif
    if(result!=0) return 1;

    //result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 10, SRK_PASSWD);
    result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
#if DEBUG
    DBG("Set Secret\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Set Secret\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hSigning_key);
#if DEBUG
    DBG("Context create\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Context create\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, MY_UUID, &hSigning_key);
#if DEBUG
    DBG("Load key\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Load key\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hHash);
#if DEBUG
    DBG("Create Object\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Create Object\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Hash_SetHashValue(hHash, 20, str);
#if DEBUG
    DBG("Set Hash\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Set Hash\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Hash_VerifySignature(hHash, hSigning_key, 256, data);
#if DEBUG
    DBG("Verify\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Verify\", 1)\
			'");
#endif
     if(result==0) return 1;

     result = Tspi_Policy_FlushSecret(hSigning_key);
#if DEBUG
     DBG("Flush Secret\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Flush Secret\", 1)\
			'");
#endif
     if(result!=0) return 1;

     result = Tspi_Context_Close(hContext);
#if DEBUG
     DBG("Close TPM\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Close TPM\", 1)\
			'");
#endif
     if(result!=0) return 1;

     return 0;
}

int receive_firmware(BIO *sbio)
{
    FILE* fp = NULL;
    char buf[1024];
    int len = 1;

    printf("Firmware receive start\n");
    /// firmware rececive start ///
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Firmware receive start\", 1)\
			'");

    if(!(fp = fopen("firmware", "wt")))
    {
        printf("File open error\n");
        return 1;
    }

    while(len>0)
    {
        if((len = BIO_read(sbio, buf, 1024)) < 0)
        {
            printf("BIO_read failed\n");
            return 1;
        }

        fwrite((void*)buf, 1, len, fp);
		len = 0;
    }
    fclose(fp);

    /// firmware signature receive start ///
    len = 1;
    memset(buf, 0, sizeof(buf));
    if(!(fp = fopen("Signature2", "wb")))
    {
        printf("File open failed\n");
        return 1;
    }
    while(len>0)
    {
        if((len = BIO_read(sbio, buf, 1024)) < 0)
        {
            printf("BIO_read faile\n");
            return 1;
        }
        fwrite((void*)buf, 1, len, fp);
		len = 0;
    }
    fclose(fp);

    return 0;
}

int Update_Daemon(BIO* sbio)
{

	if(receive_firmware(sbio)!=0)
	{
		printf("Data receive failed\n");
		system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Data receive failed\", 2)\
			'");


		return 1;
	}
	
    //NVRAM all data verify using while or for
	if(verify_firmware_version_Signature()==0)
	{
		printf("Firmware_version_Signature verify failed\n");
		system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Firmware_version_Signature verify failed\", 2)\
			'");

		return 1;
	}

	if(generate_Signature()!=0)
	{
		printf("Signature generation failed\n");
		system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_fw_update (`id`, `update_log`, `update_parity`) values(1001, \"Signature generation failed\", 2)\
			'");

		return 1;
	}

   return 0; 
}
