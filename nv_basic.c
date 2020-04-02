#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_tpm2_types.h>
#include<tss2/tss2_mu.h>
#include<tss2/tss2_rc.h>


#include "tcti_helper/tcti_helper.h"

#define TSSWG_INTEROP 1
#define TSS_SAPI_FIRST_FAMILY 2
#define TSS_SAPI_FIRST_LEVEL 1
#define TSS_SAPI_FIRST_VERSION 108

void HexDump(uint8_t * array, uint32_t size);

int main(){
    ESYS_TR nvHandle = ESYS_TR_NONE;

    TPM2B_NV_PUBLIC *nvPublic = NULL;
    TPM2B_NAME *nvName = NULL;
    TPM2B_MAX_NV_BUFFER *nv_test_data2 = NULL;

    TSS2_RC rc;                                                  //返回结果
    size_t tcti_size;                                           //TCTI对象的大小
    TSS2_TCTI_CONTEXT *tcti_context; //程序使用的TCTI CONTEXT
    TSS2_TCTI_CONTEXT *tcti_inner;      //连接不同设备的TCTI CONTEXT
    ESYS_CONTEXT *esys_context;           // Esys CONTEXT
    TSS2_ABI_VERSION abiVersion =
        { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL,
        TSS_SAPI_FIRST_VERSION };

    //默认的TCTI设置 SOCKET_TCTI /dev/tpm0 localhost 2321
    test_opts_t opts = {
        .tcti_type = TCTI_DEFAULT,
        .device_file = DEVICE_PATH_DEFAULT,
        .socket_address = "localhost",
        .socket_port = PORT_DEFAULT,
    };  

    //从环境变量内获取TCTI配置
    get_test_opts_from_env(&opts);
    if (sanity_check_test_opts(&opts) != 0) {
        printf("TPM Startup FAILED! Error in sanity check\r\n");
        exit(1);
    }

    //不同设备TCTI层的初始化：
    //SOCKET_TCTI：
    //内部首先调用Tss2_Tcti_Mssim_Init(NULL, &size, conf_str);得到size
    //根据返回的size calloc 返回的(TSS2_TCTI_CONTEXT*) tcti_ctx所需的空间
    //然后将tcti_ctx传入Tss2_Tcti_Mssim_Init(tcti_ctx, &size, conf_str);进行初始化
    tcti_inner = tcti_init_from_opts(&opts);
    if (tcti_inner == NULL) {
        printf("TPM Startup FAILED! Error tcti init");
        exit(1);
    }

    //TCTI_PROXY 的初始化，和上面流程相仿
    //获取TSS2_TCTI_CONTEXT_PROXY的size
    //TSS2_TCTI_CONTEXT_PROXY是写好的struct
    /*
    typedef struct {
    uint64_t magic;
    uint32_t version;
    TSS2_TCTI_TRANSMIT_FCN transmit;
    TSS2_TCTI_RECEIVE_FCN receive;
    TSS2_RC (*finalize) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*cancel) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*getPollHandles) (TSS2_TCTI_CONTEXT *tctiContext,
              TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles);
    TSS2_RC (*setLocality) (TSS2_TCTI_CONTEXT *tctiContext, uint8_t locality);
    TSS2_TCTI_CONTEXT *tctiInner;
    enum state state;
    } TSS2_TCTI_CONTEXT_PROXY;
    */
    rc = tcti_proxy_initialize(NULL, &tcti_size, tcti_inner);
    if (rc != TSS2_RC_SUCCESS) {
        printf("tcti initialization FAILED! Response Code : 0x%x\r\n", rc);
        return rc;
    }

    //根据得到的size calloc空间
    tcti_context  =  calloc(1, tcti_size);
    if (tcti_inner == NULL) {
        printf("TPM Startup FAILED! Error tcti init\r\n");
        exit(1);
    }

    //传入pointer，初始化
    //定义MAGIC  VERSION
    //transmit  receive finalize的三个函数
    rc = tcti_proxy_initialize(tcti_context, &tcti_size, tcti_inner);
    if (rc != TSS2_RC_SUCCESS) {
        printf("tcti initialization FAILED! Response Code : 0x%x\r\n", rc);
        return 1;
    }

    //根据tcti_context初始化ESYS_CONTEXT
    rc = Esys_Initialize(&esys_context, tcti_context, &abiVersion);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Initialize FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }

    //启动
    rc = Esys_Startup(esys_context, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        printf("Esys_Startup FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }

    //esys_context->timeout = timeout;
    rc = Esys_SetTimeout(esys_context, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_SetTimeout FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }


    TPM2B_AUTH auth = {.size = 20,
                       .buffer={10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                                20, 21, 22, 23, 24, 25, 26, 27, 28, 29}};

    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex =TPM2_NV_INDEX_FIRST,
            .nameAlg = TPM2_ALG_SHA1,
            .attributes = (
                TPMA_NV_OWNERWRITE |
                TPMA_NV_AUTHWRITE |
                TPMA_NV_WRITE_STCLEAR |
                TPMA_NV_AUTHREAD |
                TPMA_NV_OWNERREAD |
                TPM2_NT_EXTEND << TPMA_NV_TPM2_NT_SHIFT
                ),
            .authPolicy = {
                 .size = 0,
                 .buffer = {},
             },
            .dataSize = 20,
        }
    };

    rc = Esys_NV_DefineSpace (
        esys_context,
        ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &auth,
        &publicInfo,
        &nvHandle);

 if (rc != TPM2_RC_SUCCESS ) {
        printf("Error esys define nv space! Response Code : 0x%x\r\n", rc);
        goto error;
    }

    TPM2B_MAX_NV_BUFFER nv_test_data = { .size = 20,
                                         .buffer={0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                                  1, 2, 3, 4, 5, 6, 7, 8, 9}};

    rc = Esys_NV_ReadPublic(
        esys_context,
        nvHandle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nvPublic,
        &nvName);

    HexDump( nvName->name , nvName->size);
    if (rc != TPM2_RC_SUCCESS) {
        printf("Error: nv read public! Response Code : 0x%x\r\n", rc);
        goto error;
    }


    rc = Esys_NV_Extend (
        esys_context,
        nvHandle,
        nvHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nv_test_data);

     if (rc != TPM2_RC_SUCCESS) {
        printf("Error esys nv write! Response Code : 0x%x\r\n", rc);
        goto error;
    }
    Esys_Free(nvPublic);
    Esys_Free(nvName);

    rc = Esys_NV_ReadPublic(
        esys_context,
        nvHandle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nvPublic,
        &nvName);

     if (rc != TPM2_RC_SUCCESS) {
        printf("Error: nv read public! Response Code : 0x%x\r\n", rc);
        goto error;
    }    

    
    rc = Esys_NV_Read(
        esys_context,
        nvHandle,
        nvHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        20,
        0,
        &nv_test_data2);

    if (rc != TPM2_RC_SUCCESS) {
        printf("Error: Error esys nv read! Response Code : 0x%x\r\n", rc);
        goto error;
    }    

    printf("after extend\n");
    HexDump(nv_test_data2->buffer,nv_test_data2->size);

    Esys_Free(nvPublic);
    Esys_Free(nvName);

    rc = Esys_NV_ReadPublic(
        esys_context,
        nvHandle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nvPublic,
        &nvName);

//unseal无法使用 不要用
    // TPM2B_SENSITIVE_DATA* unseal_data;
    // rc = Esys_Unseal(
    //     esys_context,
    //     nvHandle,
    //     ESYS_TR_PASSWORD,
    //     ESYS_TR_NONE,
    //     ESYS_TR_NONE,
    //     &unseal_data
    // );

    // if (rc != TPM2_RC_SUCCESS) {
    //     printf("Error: unseal data! Response Code : 0x%x\r\n", rc);
    //     goto error;
    // }    

    // printf("unseal data\n");
    // HexDump(unseal_data->buffer,unseal_data->size);

    Esys_Free(nvPublic);
    Esys_Free(nvName);

    rc = Esys_NV_ReadPublic(
        esys_context,
        nvHandle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nvPublic,
        &nvName);
 if (rc != TPM2_RC_SUCCESS) {
        printf("Error: nv read public! Response Code : 0x%x\r\n", rc);
        goto error;
    }    

    rc = Esys_NV_UndefineSpace(esys_context,
                              ESYS_TR_RH_OWNER,
                              nvHandle,
                              ESYS_TR_PASSWORD,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE
                              );
    if (rc != TPM2_RC_SUCCESS) {
        printf("Error: NV_UndefineSpace! Response Code : 0x%x\r\n", rc);
        goto error;
    }    

    Esys_Free(nvPublic);
    Esys_Free(nvName);
    Esys_Free(nv_test_data2);
    return EXIT_SUCCESS;

 error:

    if (nvHandle != ESYS_TR_NONE) {
        if (Esys_NV_UndefineSpace(esys_context,
                                  ESYS_TR_RH_OWNER,
                                  nvHandle,
                                  ESYS_TR_PASSWORD,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE) != TSS2_RC_SUCCESS) {
        }
    }


    Esys_Free(nvPublic);
    Esys_Free(nvName);
    Esys_Free(nv_test_data2);
    return EXIT_FAILURE;
    }

    void HexDump(uint8_t * array, uint32_t size)
{
    printf("value:  0x");
    for(uint32_t i = 0; i < size; i++){    
        printf("%02x", array[i] );
    }
    printf("\r\n");
}