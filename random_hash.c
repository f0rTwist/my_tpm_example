

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_tpm2_types.h>

#include "tcti_helper/tcti_helper.h"

#define TSSWG_INTEROP 1
#define TSS_SAPI_FIRST_FAMILY 2
#define TSS_SAPI_FIRST_LEVEL 1
#define TSS_SAPI_FIRST_VERSION 108

void HexDump(uint8_t * array, uint32_t size);
void printHash(uint8_t * bytes, uint32_t size, int hasht);

int
main(int argc, char *argv[])
{
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
    tcti_context = calloc(1, tcti_size);
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

//     typedef struct {
//     UINT16 size;
//     BYTE buffer[sizeof(TPMU_HA)];
//      } TPM2B_DIGEST;
//      就是个存数据的struct，B是byte
    TPM2B_DIGEST *randomBytes;

    rc = Esys_GetRandom(esys_context,   //Context肯定要传
                        ESYS_TR_NONE,                       //这三个都是
                        ESYS_TR_NONE,                       //session handle
                        ESYS_TR_NONE,
                        48,                                                    //返回的字节数
                        &randomBytes);                         //放到这里面

    if (rc != TPM2_RC_SUCCESS) {
        printf("Esys_GetRandom FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }

    //输出这个随机数
    printf("Random bytes\r\n");
    HexDump(randomBytes->buffer, 48);

    // typedef struct {
    // UINT16 size;
    // BYTE buffer[1024];
    // } TPM2B_MAX_BUFFER;
    char str[30] = {0};
    printf("\nInput data:");
     scanf("%s", str);
     UINT16 size = strlen(str);
     
    TPM2B_MAX_BUFFER data ;
    data.size = size;
    memcpy(data.buffer,str,size+1);
    TPMI_ALG_HASH hashAlg256 = TPM2_ALG_SHA256;             // TPM2_ALG_ID uint16 
    TPMI_ALG_HASH hashAlg1 = TPM2_ALG_SHA1;             // TPM2_ALG_ID uint16 
    TPMI_ALG_HASH hashAlg512 = TPM2_ALG_SHA512;             // TPM2_ALG_ID uint16 
    TPMI_RH_HIERARCHY hierarchy = TPM2_RH_OWNER;  //uint32 TPM2_HANDLE
    TPM2B_DIGEST *outHash256;                                                          //输出hash的，定义同上
    TPM2B_DIGEST *outHash1;                                                          //输出hash的，定义同上
    TPM2B_DIGEST *outHash512;                                                          //输出hash的，定义同上
    TPMT_TK_HASHCHECK *validation;                                      //Ticket 拿来干啥的
    
    //HexDump2(data.buffer,size);                 

    rc = Esys_Hash(                             
        esys_context,                                               //context肯定要传
        ESYS_TR_NONE,                                         //同样的三个session handle
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &data,                                                              //要加密的数据
        hashAlg256,                                                          //hash算法
        hierarchy,                                                       //TPM hierarchy 
        &outHash256,                                                      //输出的hash
        &validation);                                                  //Ticket
        
    if (rc != TPM2_RC_SUCCESS) {
        printf("Esys_Hash FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }

    rc = Esys_Hash(                             
        esys_context,                                               //context肯定要传
        ESYS_TR_NONE,                                         //同样的三个session handle
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &data,                                                              //要加密的数据
        hashAlg1,                                                          //hash算法
        hierarchy,                                                       //TPM hierarchy 
        &outHash1,                                                      //输出的hash
        &validation);                                                  //Ticket
        
    if (rc != TPM2_RC_SUCCESS) {
        printf("Esys_Hash FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }

    rc = Esys_Hash(                             
        esys_context,                                               //context肯定要传
        ESYS_TR_NONE,                                         //同样的三个session handle
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &data,                                                              //要加密的数据
        hashAlg512,                                                          //hash算法
        hierarchy,                                                       //TPM hierarchy 
        &outHash512,                                                      //输出的hash
        &validation);                                                  //Ticket
        
    if (rc != TPM2_RC_SUCCESS) {
        printf("Esys_Hash FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }

    //输出hash结果
    printHash(outHash1->buffer, 20, 1);
    printHash(outHash256->buffer, 32, 256);
    printHash(outHash512->buffer,64, 512);
    printf("\r\n");

    Esys_Finalize(&esys_context);
    //Tss2_Tcti_Finalize由之前指定的函数而定，这里是
    //memset(tctiContext, 0, sizeof(TSS2_TCTI_CONTEXT_PROXY));
    Tss2_Tcti_Finalize  (tcti_inner);
    Tss2_Tcti_Finalize  (tcti_context); 

    return 0;

error:
    //error, clean up and quit
    Esys_Finalize(&esys_context);
    Tss2_Tcti_Finalize  (tcti_inner);
    Tss2_Tcti_Finalize  (tcti_context);
    return 0;
}

//一个简单的输出函数
void HexDump(uint8_t * array, uint32_t size)
{
    for(uint32_t i = 0; i < size; i++){
        if((i % 8) == 0){
            printf("\r\n");
            printf("%06d:      ", i);
        }
        printf("0x%02x ", array[i] );
    }
    printf("\r\n");
}

void printHash(uint8_t * bytes, uint32_t size, int h){
    printf("\nSHA%d:",h);
    for(int i=0;i<size;i++){
        printf("%02x",bytes[i]);
    }
    printf("\r\n");
}

