#include <stdio.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>
#include <tss/tss_error.h>

#include <openssl/sha.h>

#define SIGN_KEY_UUID {0, 0, 0, 0, 0, {0, 0, 0, 5, 32}}
#define DBG(message, tResult) printf("(Line%d, %s) %s returned 0x%08x. %s.\n\n",__LINE__ ,__func__ , message, tResult, (char *)Trspi_Error_String(tResult));
#define DEBUG 1

unsigned char xor_result[20];

int get_hash_value()
{
    FILE* fp; // File Pointer
    int i; // for value
    unsigned char buf[1024]; // File read date value
    unsigned char digest[20];
    SHA_CTX ctx;

    /// u-boot hash start ///
    if(!(fp=fopen("/boot/u-boot.bin", "rb")))
    {
        printf("File open error\n");
        return 1;
    }
    SHA1_Init(&ctx);
    while((i = fread(buf, 1, sizeof(buf), fp)) > 0)
    {
        SHA1_Update(&ctx, buf, i);
    }
    SHA1_Final(xor_result, &ctx);
    fclose(fp);

    /// image.fit hash start ///
    if(!(fp=fopen("/boot/image.fit", "rb")))
    {
        printf("File open error\n");
        return 1;
    }
    SHA1_Init(&ctx);
    while((i = fread(buf, 1, sizeof(buf), fp)) > 0)
    {
        SHA1_Update(&ctx, buf, i);
    }
    SHA1_Final(digest, &ctx);
    fclose(fp);

    for(i=0; i<20; i++)
        xor_result[i] = xor_result[i]^digest[i];

    if(!(fp=fopen("serial", "rb")))
    {
        printf("File open error\n");
        return 1;
    }
    SHA1_Init(&ctx);
    while((i = fread(buf, 1, sizeof(buf), fp)) > 0)
    {
        SHA1_Update(&ctx, buf, i);
    }
    SHA1_Final(digest, &ctx);
    fclose(fp);

    for(i=0; i<20; i++)
        xor_result[i] = xor_result[i]^digest[i];

    return 0;
}

int main(void)
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
    BYTE *sig, *pubKey;
    UINT32 srk_authusage, sigLen, pubKeySize;
    FILE* fp;

    result = Tspi_Context_Create(&hContext);
#if DEBUG
    DBG("Create TPM Context\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_Context_Connect(hContext, NULL);
#if DEBUG
    DBG("Connect to TPM\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hSigning_key);
#if DEBUG
    DBG("Create the key object\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_SetAttribUint32(hSigning_key, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_SIGSCHEME, TSS_SS_RSASSAPKCS1V15_SHA1);
#if DEBUG
    DBG("Set the key's padding type\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
#if DEBUG
    DBG("Get SRK handle\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_GetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, &srk_authusage);
#if DEBUG
    DBG("Get Attribute\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
#if DEBUG
    DBG("GetPolicyObject\n", result);
#endif
    if(result!=0) return 1;

    //result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 10, SRK_PASSWD);
    result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
#if DEBUG
    DBG("Set Secret\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_Key_CreateKey(hSigning_key, hSRK, 0);
#if DEBUG
    DBG("Create Signing key\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_Key_LoadKey(hSigning_key, hSRK);
#if DEBUG
    DBG("Load Key\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_Context_RegisterKey(hContext, hSigning_key, TSS_PS_TYPE_SYSTEM, MY_UUID, TSS_PS_TYPE_SYSTEM, SRK_UUID);
#if DEBUG
    DBG("Register key\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_Key_GetPubKey(hSigning_key, &pubKeySize, &pubKey);
#if DEBUG
    DBG("Get Pub Key\n", result);
#endif
    if(result!=0) return 1;

    get_hash_value();

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hHash);
#if DEBUG
    DBG("Create Object\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_Hash_SetHashValue(hHash, 20, xor_result);
#if DEBUG
    DBG("Set Hash\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_Hash_Sign(hHash, hSigning_key, &sigLen, &sig);
#if DEBUG
    DBG("Generate Signature\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0, &hNVStore);
#if DEBUG
    DBG("Create NV Object\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0, 0x00011106);
#if DEBUG
    DBG("Set NVRAM index\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_PERMISSIONS, 0, TPM_NV_PER_OWNERWRITE);
#if DEBUG
    DBG("Set Policy\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_DATASIZE, 0, 0x100);
#if DEBUG
    DBG("Set NVRAM size\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hNVPolicy);
#if DEBUG
    DBG("Set Secret\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_Policy_SetSecret(hNVPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
#if DEBUG
    DBG("TPM SetSecret\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_Policy_AssignToObject(hNVPolicy, hNVStore);
#if DEBUG
    DBG("TPM AssignToObject\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_NV_DefineSpace(hNVStore, 0, 0);
#if DEBUG
    DBG("Create NVRAM space\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_NV_WriteValue(hNVStore, 0, sigLen, sig);
#if DEBUG
    DBG("Write to the TPM NVRAM\n", result);
#endif
    if(result!=0) return 1;

//    result = Tspi_Policy_FlushSecret(hSigning_key);
//#if DEBUG
//    DBG("Flush Secret\n", result);
//#endif
//    if(result!=0) return 1;

    result = Tspi_Context_FreeMemory(hContext, NULL);
#if DEBUG
    DBG("Free memory\n", result);
#endif
    if(result!=0) return 1;

    result = Tspi_Context_Close(hContext);
#if DEBUG
    DBG("Close TPM\n", result);
#endif
    if(result!=0) return 1;

    return 0;
}
