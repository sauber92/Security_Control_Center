#include "Secure_boot.h"

char get_plain(unsigned char ch)
{
	ch = ch % 26;

	return (char)(97 + (ch)%26);
}

void createSRK(unsigned char* SRK_PASSWD, unsigned char* xor_result)
{
    int i;
    for(i=0; i<20; i++)
        SRK_PASSWD[i] = get_plain(xor_result[i]);
}

int secure_boot_hash(unsigned char* xor_result)
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
    if(!(fp = fopen("serial", "r"))) {
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

int verify_Bootloader_Signature(unsigned char* xor_result)
{
    TSS_HCONTEXT hContext; // TSS Context
    TSS_RESULT result; // TSS result print using DBG
    TSS_HKEY hSRK; // SRK value
    TSS_HPOLICY hSRKPolicy, hNVPolicy; // SRK and NVRAM configure value
    TSS_UUID MY_UUID = SIGN_KEY_UUID; // TPM Signkey save location
    TSS_UUID SRK_UUID = TSS_UUID_SRK;; // TPM SRK save location
    TSS_HKEY hSigning_key; // TPM Signkey value
    TSS_FLAG initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE; // TPM Key configure value
    TSS_HHASH hHash; // TPM Hash value
    TSS_HNVSTORE hNVStore; // TPM NVRAM value
    BYTE *pubKey, *sign, *data; // Public key, Signature, NVRAM data
    UINT32 pubKeySize = 256, srk_authusage, sigLen, datasize = 256;
    unsigned char buf[256];

    result = Tspi_Context_Create(&hContext); // TPM Context init
#if DEBUG
    DBG("Create a context\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Create a context\", 1)\
			'");
#endif

    result = Tspi_Context_Connect(hContext, NULL); // TPM Context connect with TPM
#if DEBUG
    DBG("Connect to TPM\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Connect to TPM\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0, &hNVStore);
#if DEBUG
    DBG("Create NV object\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Create NV object\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0, 0x00011109); // TPM NVRAM value configure
#if DEBUG
    DBG("Set NVRAM index\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Set NVRAM index\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_PERMISSIONS, 0, TPM_NV_PER_OWNERWRITE); //TPM NVRAM value configure
#if DEBUG
    DBG("Set NVRAM policy\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Set NVRAM policy\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_DATASIZE, 0, 0x200); // TPM NVRAM value configure
#if DEBUG
    DBG("Set NVRAM size\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Set NVRAM size\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_NV_ReadValue(hNVStore, 0, &datasize, &data); // TPM NVRAM read(read previous save signature(u-boot.bin and image.fit hash))
#if DEBUG
    DBG("Read value from NVRAM\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Read value from NVRAM\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK); // Load TPM SRK
#if DEBUG
    DBG("Get SRK handle\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Get SRK handle\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_GetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, &srk_authusage); // SRK configure load
#if DEBUG
    DBG("Get SRK Attribute\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Get SRK Attribute\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy); // Get TPM SRK configure
#if DEBUG
    DBG("Get SRK configure\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Get SRK configure\", 1)\
			'");
#endif
    if(result!=0) return 1;

//    result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 10, SRK_PASSWD); // Set SRK
    result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
#if DEBUG
    DBG("Set SRK\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Get SRK\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hSigning_key); // Create RSA Key(Singing key) Object
#if DEBUG
    DBG("Create RSA Object\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Create RSA Object\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, MY_UUID, &hSigning_key); // Load Signing key(Signing key was created(when u-boot.bin and image.fit hash and create signature)
#if DEBUG
    DBG("Load Signing key\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Load Signing key\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hHash); // Create Hash(SHA1) Object
#if DEBUG
    DBG("Create Hash object\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Create Hash object\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Hash_SetHashValue(hHash, 20, xor_result); // Set xor_result in Hash object
#if DEBUG
    DBG("Set Hash\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Set Hash\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Hash_VerifySignature(hHash, hSigning_key, 256, data); // Compare xor_result and NVRAM data
#if DEBUG
    DBG("Verify Signature\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Verify Signature\", 1)\
			'");
#endif
    if(result!=0) return 1;

//    result = Tspi_Policy_FlushSecret(hSigning_key); // Signing key configure clear
//#if DEBUG
//    DBG("Flush signing key\n", result);
//#endif
//    if(result!=0) return 1;

    result = Tspi_Context_FreeMemory(hContext, NULL); // TPM Context memory free
#if DEBUG
    DBG("Context Free\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"Context Free\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_Close(hContext); // TPM Close
#if DEBUG
    DBG("TPM Close\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_key_manage (`id`, `key_log`, `key_parity`) values(1001, \"TPM Close\", 1)\
			'");
#endif
    if(result!=0) return 1;

    return 0;
}

int changeSRKPW(unsigned char* SRK_PASSWD)
{
    TSS_HTPM hTPM; // TPM value
    TSS_HPOLICY hTPMPolicy, hNewPolicy; // TPM value configure
    TSS_HCONTEXT hContext; // TPM Context
    TSS_RESULT result; // TPM result print using DBG
    TSS_HKEY hSRK; // TPM SRK value
    TSS_UUID SRK_UUID = TSS_UUID_SRK; // TPM SRK save location

    result = Tspi_Context_Create(&hContext); // Create TPM Context
#if DEBUG
    DBG("Create TPM Context\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_boot (`id`, `boot_log`, `boot_parity`) values(1001, \"Create TPM Context\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_Connect(hContext, NULL); // Connect TPM and TPM Context
#if DEBUG
    DBG("Connect TPM\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_boot (`id`, `boot_log`, `boot_parity`) values(1001, \"Connect TPM\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_GetTpmObject(hContext, &hTPM); // TPM Object configure load
#if DEBUG
    DBG("Load TPM object configure\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_boot (`id`, `boot_log`, `boot_parity`) values(1001, \"Load TPM object configure\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTPMPolicy); // Get TPM configure
#if DEBUG
    DBG("Get TPM configure\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_boot (`id`, `boot_log`, `boot_parity`) values(1001, \"Get TPM configure\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_PLAIN, 1, "1"); // Set SRK
#if DEBUG
    DBG("Set SRK\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_boot (`id`, `boot_log`, `boot_parity`) values(1001, \"Set SRK\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hNewPolicy); // Create new SRK configure object
#if DEBUG
    DBG("Create New SRK configure object\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_boot (`id`, `boot_log`, `boot_parity`) values(1001, \"Create New SRK configure object\", 1)\
			'");
#endif
    if(result!=0) return 1;

//    result = Tspi_Policy_SetSecret(hNewPolicy, TSS_SECRET_MODE_PLAIN, 10, SRK_PASSWD); // Set new SRK Configure
    result = Tspi_Policy_SetSecret(hNewPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
#if DEBUG
    DBG("Set New SRK Configure\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_boot (`id`, `boot_log`, `boot_parity`) values(1001, \"Set New SRK Configure\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK); // Load TPM SRK
#if DEBUG
    DBG("Load TPM SRK\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_boot (`id`, `boot_log`, `boot_parity`) values(1001, \"Load TPM SRK\", 1)\
			'");
#endif
    if(result!=0) return 1;

    result = Tspi_ChangeAuth(hSRK, hTPM, hNewPolicy); // Change New SRK PW
#if DEBUG
    DBG("Change New SRK PW\n", result);
	system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_boot (`id`, `boot_log`, `boot_parity`) values(1001, \"Change New SRK PW\", 1)\
			'");
#endif
    if(result!=0) return 1;

    return 0;
}

int Secure_Boot_Daemon(BIO* sbio)
{
	unsigned char xor_result[20];
	unsigned char SRK_PASSWD[20];

    if(secure_boot_hash(xor_result)!=0)
    {
        printf("Secure_boot_hash failed\n");
		BIO_write(sbio, "Secure_boot_hash failed", 10);
		
		system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_boot (`id`, `boot_log`, `boot_parity`) values(1001, \"Secure_boot_hash failed\", 2)\
			'");

        return 1;
    }

    createSRK(SRK_PASSWD, xor_result);

    if(changeSRKPW(SRK_PASSWD)!=0)
    {
        printf("change_SRK_PW failed\n");
		BIO_write(sbio, "change_SRK_PW failed", 10);
		
		system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_boot (`id`, `boot_log`, `boot_parity`) values(1001, \"change_SRK_PW failed\", 2)\
			'");

        return 1;
    }

    if(verify_Bootloader_Signature(xor_result)!=0)
    {
        printf("Bootloader Signature Verify failed\n");
		BIO_write(sbio, "Bootloader Signature Verify failed", 10);
	
		system("mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e '\
			insert into secure_boot (`id`, `boot_log`, `boot_parity`) values(1001, \"Bootloader Signature Verify failed\", 2)\
			'");

        return 1;
    }

	return 0;
}
