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
void errorHandler(ESYS_CONTEXT *esys_context,TSS2_TCTI_CONTEXT *tcti_inner,TSS2_TCTI_CONTEXT *tcti_context){
    Esys_Finalize(&esys_context);
    Tss2_Tcti_Finalize  (tcti_inner);
    Tss2_Tcti_Finalize  (tcti_context);
    exit(-1);
}

int main(int argc, char *argv[])
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
    tcti_context = (TSS2_TCTI_CONTEXT*)calloc(1, tcti_size);
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
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    //启动
    rc = Esys_Startup(esys_context, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        printf("Esys_Startup FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    //esys_context->timeout = timeout;
    rc = Esys_SetTimeout(esys_context, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_SetTimeout FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    int selected = 0;
    
    printf("Select a PCR register(0-16or23):");

    scanf("%d",&selected);

    ESYS_TR pcrHandle_handle = ESYS_TR_PCR0 + selected; //选择的pcr号，下面PcrExtend也用到了
    UINT32 pcrUpdateCounter;                                //好像是用来计数的
    TPML_PCR_SELECTION *pcrSelectionOut;  //字面意思，暂时没发现有什么用
    TPML_DIGEST *pcrValues;                                   //这个是读出来的pcr值
                                                                                             //同属TPML_DIGEST 和上面的TPML_DIGEST_VALUE
                                                                                             //区别就是这个没有hash算法只有一组一组的数据

    size_t  selectionSize = selected/8 + 1;
    BYTE* selection = (BYTE*)calloc(selectionSize,sizeof(int));

    //下面是使用位运算计算选择bitmap来表示选中的PCR
    for(uint32_t i=0;i<selectionSize;i++)
    {
        selection[i] = i==selectionSize-1?1<<(selected%8):0b00000000;
    }

    //下面是TPML_PCR_SELECTION，用于选择某些幸运PCR
    //PCR对于SHA1 SHA256 SHA384 SHA512有不同的寄存器，看上去是独立的
    //count对应选择的类型，pcrSelection对应的是某个类型的选择集合

    //pcrSelection里面有hash算法，选择数组PcrSelect的size（也是最大是3）
    //然后是pcrselect,用来标记被选中的幸运PCR，使用了一种很省空间但是需要做位运算的方式
    //每个BYTE对应的是从小到大的8个PCR，也就是说每一位对应一个，一个BYTE对应8个
    //可以选择读到任意个PCR..这里更正一下 但是出来的digest一共只能有8个.还在继续研究
    //e.g. 选择第 0 ，1  ，9个 -> 0000 0011 0000 0010->03 , 02
    //这里坑我好久++。
    TPML_PCR_SELECTION pcrSelectionIn = {
        .count = 2,
        .pcrSelections = {
            { .hash = TPM2_ALG_SHA1,
              .sizeofSelect = 3,
              .pcrSelect = { }
            },
            { .hash = TPM2_ALG_SHA256,
              .sizeofSelect = 3,
              .pcrSelect = { }
            },
        }
    };

	//把选择数据放进去
    memcpy(pcrSelectionIn.pcrSelections[0].pcrSelect,selection,selectionSize+1);
    memcpy(pcrSelectionIn.pcrSelections[1].pcrSelect,selection,selectionSize+1);
    printf("\n%dth Selected,Byte ",selected);
    HexDump(pcrSelectionIn.pcrSelections[0].pcrSelect,selectionSize);

    rc = Esys_PCR_Read(
        esys_context,                                                           //上下文
        ESYS_TR_NONE,                                                     //read不需要特殊的session handle
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &pcrSelectionIn,                                                      //选择pcr
        &pcrUpdateCounter,                                              //好像是更新计数。待验证
        &pcrSelectionOut,                                                   //这个选择out出来不知道有啥用
        &pcrValues                                                                  //读出来的值
    ); 

    if (rc != TPM2_RC_SUCCESS) {
        printf("Esys_PCR_Read FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    printf("Before PCR_Event:\r\n");
    for(uint32_t i=0;i<pcrValues->count;i++){
        TPM2B_DIGEST t = pcrValues->digests[i];
        HexDump(t.buffer,t.size);
        }

    char str[30] = {0};
    printf("\nInput event data:");
     scanf("%s", str);
     UINT16 size = strlen(str); 

    //这个PCREVENT,一开始我以为是重设pcr的...所以虽然可以用了这个是用来干嘛的
    TPM2B_EVENT eventData = { .size = size};              //eventData，也是和TPM2B_DATA一样的结构
    memcpy(eventData.buffer,str,size+1);
    TPML_DIGEST_VALUES *digestsEvent;                   //这个应该是放摘要的值的，结果来看是SHA1对eventdata的摘要
    //digestsEvent->count = 1;
   // digestsEvent->digests->hashAlg = TPM2_ALG_SHA256;

    printf("\nData in TPM2B_EVENT "); 
    HexDump(eventData.buffer,size);

    rc = Esys_PCR_Event(
        esys_context,
        pcrHandle_handle,          //目标pcr
        ESYS_TR_PASSWORD,     //不知道为什么设这个PASSWORD
        ESYS_TR_NONE,                //这里用NONE不行
        ESYS_TR_NONE,
        &eventData,                         //扩展的data
        &digestsEvent);                   //digestevent 

    if (rc != TPM2_RC_SUCCESS) {
        printf("Esys_PCR_Event FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

printf("PCR Event digests:\r\n");
   for(uint32_t i=0;i<digestsEvent->count;i++){
       switch (digestsEvent->digests[i].hashAlg){
           case TPM2_ALG_SHA1:
                HexDump(digestsEvent->digests[i].digest.sha1,20);
                break;
            case TPM2_ALG_SHA256:
                HexDump(digestsEvent->digests[i].digest.sha256,32);
                break;
            case TPM2_ALG_SHA512:
                HexDump(digestsEvent->digests[i].digest.sha512,64);
                break;
       }
   }
     
    
        rc = Esys_PCR_Read(
        esys_context,                                                           //上下文
        ESYS_TR_NONE,                                                     //read不需要特殊的session handle
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &pcrSelectionIn,                                                      //选择pcr
        &pcrUpdateCounter,                                              //好像是更新计数。待验证
        &pcrSelectionOut,                                                   //这个选择out出来不知道有啥用
        &pcrValues                                                                  //读出来的值
    ); 

    if (rc != TPM2_RC_SUCCESS) {
        printf("Esys_PCR_Read FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    printf("After PCR_Event:\r\n");
    for(uint32_t i=0;i<pcrValues->count;i++){
        TPM2B_DIGEST t = pcrValues->digests[i];
        HexDump(t.buffer,t.size);
    }   


    char str2[30] = {0};
    printf("\nInput extend data:");
     scanf("%s", str2);
     UINT16 size2 = strlen(str2); 

    //这个TPML_DIGEST_VALUES 可以放16个TPMT_HA
    //16对应pcr存储数量 TPM2_NUM_PCR_BANKS
    //目前测试扩展操作只能操作一个
    //每个digest有一个hash算法和它对应的的值
    //hashAlg指定了扩展的类型 digest是各类PCR寄存器扩展的值，要放在对应位置
    TPML_DIGEST_VALUES digestsData = {
        .count = 1,
        .digests = {
            {
                .hashAlg = TPM2_ALG_SHA256,
                .digest = {
                    .sha1 = { }
                }
            },
        }};
    memcpy((digestsData.digests->digest.sha1),str2,size2);
    memcpy((digestsData.digests->digest.sha256),str2,size2);
    printf("\nData in TPML_DIGEST_VALUES->TPMT_HA->TPMU_HA "); 
    HexDump(digestsData.digests->digest.sha1,size2);

    rc = Esys_PCR_Extend(
        esys_context,
        pcrHandle_handle,               //目标pcr
        ESYS_TR_PASSWORD,           //这里同上
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &digestsData                                    //扩展的数据
        );

    if (rc != TPM2_RC_SUCCESS) {
        printf("Esys_PCR_exetend FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    rc = Esys_PCR_Read(
        esys_context,                                                           //上下文
        ESYS_TR_NONE,                                                     //read不需要特殊的session handle
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &pcrSelectionIn,                                                      //选择pcr
        &pcrUpdateCounter,                                              //好像是更新计数。待验证
        &pcrSelectionOut,                                                   //这个选择out出来不知道有啥用
        &pcrValues                                                                  //读出来的值
    ); 

    printf("After PCR_Extend:\r\n");
    if (rc != TPM2_RC_SUCCESS) {
        printf("Esys_PCR_Read FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    for(uint32_t i=0;i<pcrValues->count;i++){
        TPM2B_DIGEST t = pcrValues->digests[i];
        HexDump(t.buffer,t.size);
    }   

      Esys_Finalize(&esys_context);
    //Tss2_Tcti_Finalize由之前指定的函数而定，这里是
    //memset(tctiContext, 0, sizeof(TSS2_TCTI_CONTEXT_PROXY));
    Tss2_Tcti_Finalize  (tcti_inner);
    Tss2_Tcti_Finalize  (tcti_context); 

    return 0;
}

void HexDump(uint8_t * array, uint32_t size)
{
    printf("value:  0x");
    for(uint32_t i = 0; i < size; i++){    
        printf("%02x", array[i] );
    }
    printf("\r\n");
}
