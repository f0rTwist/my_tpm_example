

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

//#define WRONG_PASSW_1
//#define WRONG_PASSW_2

void HexDump2(uint8_t * array, uint32_t size);
void HexDump(uint8_t * array, uint32_t size);
void errorHandler(ESYS_CONTEXT *esys_context,TSS2_TCTI_CONTEXT *tcti_inner,TSS2_TCTI_CONTEXT *tcti_context){
    Esys_Finalize(&esys_context);
    Tss2_Tcti_Finalize  (tcti_inner);
    Tss2_Tcti_Finalize  (tcti_context);
    exit(-1);
}

int
main(int argc, char *argv[])
{
    /*General declaration*****************************************************/
    TSS2_RC rc;
    size_t tcti_size;
    TSS2_TCTI_CONTEXT *tcti_context;
    TSS2_TCTI_CONTEXT *tcti_inner;
    ESYS_CONTEXT *esys_context;
    TSS2_ABI_VERSION abiVersion =
        { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL,
        TSS_SAPI_FIRST_VERSION };


    test_opts_t opts = {
        .tcti_type = TCTI_DEFAULT,
        .device_file = DEVICE_PATH_DEFAULT,
        .socket_address = "localhost",
        .socket_port = PORT_DEFAULT,
    };

    get_test_opts_from_env(&opts);
    if (sanity_check_test_opts(&opts) != 0) {
        printf("TPM Startup FAILED! Error in sanity check\r\n");
        exit(1);
    }
    tcti_inner = tcti_init_from_opts(&opts);
    if (tcti_inner == NULL) {
        printf("TPM Startup FAILED! Error tcti init");
        exit(1);
    }
    rc = tcti_proxy_initialize(NULL, &tcti_size, tcti_inner);
    if (rc != TSS2_RC_SUCCESS) {
        printf("tcti initialization FAILED! Response Code : 0x%x\r\n", rc);
        return rc;
    }
    tcti_context = static_cast<TSS2_TCTI_CONTEXT*> (calloc(1, tcti_size));
    if (tcti_inner == NULL) {
        printf("TPM Startup FAILED! Error tcti init\r\n");
        exit(1);
    }
    rc = tcti_proxy_initialize(tcti_context, &tcti_size, tcti_inner);
    if (rc != TSS2_RC_SUCCESS) {
        printf("tcti initialization FAILED! Response Code : 0x%x\r\n", rc);
        return 1;
    }

    rc = Esys_Initialize(&esys_context, tcti_context, &abiVersion);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Initialize FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }
    rc = Esys_Startup(esys_context, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        printf("Esys_Startup FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    rc = Esys_SetTimeout(esys_context, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_SetTimeout FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR loadedKeyHandle = ESYS_TR_NONE;

    //using password for authentication
    //此结构用于授权值->TR_SetAuth
    //使用密码身份验证
    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    //sensitive 数据 sensitive可以是加密密钥或密封数据 
    //包括TPM2B_SENSITIVE_DATA 要密封的数据，键或派生值
    //和TPM2B_AUTH USER auth机密值
    //TPM2_Create()和TPM2_CreatePrimary() (inSensitive参数)中提供给TPM的敏感值可以选择使用基于会话的标准加密技术进行加密
    //由于基于会话的加密允许使用不同的会话进行授权和加密，因此用于加密授权和其他敏感数据的会话不必与新创建对象的存储父级的授权会话相同
    //所以此程序实例中的primary和loaded的userAuth 是不一样的
    //这样可以确保控制存储父级的实体不会自动获得对子级secret值的访问权限
    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0 },
             },
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };

    //将授权值放入sensitive 
    inSensitivePrimary.sensitive.userAuth = authValuePrimary;

    //用于CreatePrimary的参数inPublic，设置了rsa加密以及一些相关的属性
    //TPM2B_PUBLIC描述了要创建的对象的所需属性。
    //TPM使用此模板指导新对象的创建
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,                                                                       //TPMI_ALG_PUBLIC 与此对象关联的算法
                                                                                                                                    //该类型可以指示对称密钥，非对称密钥或数据值
            .nameAlg = TPM2_ALG_SHA256,                                                      //TPMI_ALG_HASH 用于计算对象名称的算法 可为空
            .objectAttributes =                                                                                  //与类型一起确定此对象操作的属性
            (                                                                                                                       //下面是使用的属性说明:
                                TPMA_OBJECT_USERWITHAUTH |                              //可以为需要USER角色授权的操作提供授权
                                TPMA_OBJECT_RESTRICTED |                                      //秘钥使用限制：仅限于操纵已知格式的structures
                                 TPMA_OBJECT_DECRYPT |                                            //私有部分可用于解密
                                 TPMA_OBJECT_FIXEDTPM |                                          //好像是设置对象的hierarchy 不会改变
                                 TPMA_OBJECT_FIXEDPARENT |                                  //好像是设置对象的父对象不会改变
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),               //PM2_CreatePrimary()创建对象时，TPM生成除authValue之外的所有senstive数据
            .authPolicy = {                                                                                          //使用key的可选policy，是使用对象的nameAlg计算的。如果没有auth policy，则为空
                 .size = 0,
             },
            .parameters={
                .rsaDetail = {                                                                      //TPMU_PUBLIC_PARMS 算法或结构细节,这里type是rsa 
                 .symmetric = {                                                                                      //定义可能包含在密钥的公共部分中的参数定义结构
                     .algorithm = TPM2_ALG_AES,                                                   //对于受限解密密钥，应设置为受支持的对称算法，密钥大小和模式。
                                                                                                                                    //如果密钥不是受限解密密钥，则此字段应设置为TPM_ALG_NULL
                     .keyBits={.aes = 128},                                                                         //密钥大小
                     .mode = {.aes = TPM2_ALG_CFB} },                                                 //在parent object的参数区域中使用时，它应该是TPM_ALG_CFB

                 .scheme = {                                                                                            //对于不受限制的签名密钥  TPM_ALG_RSAPSS TPM_ALG_RSASSA或TPM_ALG_NULL
                                                                                                                                    //对于受限制的签名密钥  TPM_ALG_RSAPSS或TPM_ALG_RSASSA
                                                                                                                                    //对于不受限制的解密密钥  TPM_ALG_RSAES，TPM_ALG_OAEP或TPM_ALG_NULL 除非对象也具有sign属性
                                                                                                                                    //对于受限制的解密密钥，TPM_ALG_NULL
                      .scheme = TPM2_ALG_NULL
                  },
                 .keyBits = 2048,                                                                                   //公共模数的位数
                 .exponent = 0,                                                                                      //零，表示该指数是默认值2的16次方 + 1
                 },
             },
            .unique = {
                .rsa = {                                                                                           //唯一标识符，对于非对称密钥rsa，这将是公钥
                                                                                                                                    //TPM2B_PUBLIC_KEY_RSA 
                 .size = 0,                                                                                         
                 .buffer = {},                                                                                             //公钥的buffer
             }},
        }
    };


    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    //该结构是这里是TPM2_CreatePrimary()的输出参数，指示创建对象时在PCR状态的digest中使用的PCR
    //此参数是可选的，并没有用到
    //关于此结构体的详细信息，参阅pcr.c
    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };


    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}
    };

    //设置与ESYS_TR对象关联的身份验证值
    //这里传入长度为零的authValue 删除与对象关联的授权值 将对象的authValue重置为其创建值
    rc = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_TR_SetAuth FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    
    TPM2B_PUBLIC *outPublic;                                //和inPublic的唯一区别是uniquefiled，这里是公钥
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;

    //TPM2_Create()，TPM2_CreatePrimary()和TPM2_CreateLoaded()用于创建TPM存储hierarchy中的对象
    //TPM2_CreatePrimary()用于创建从“ Primary  Seed”派生的“ Primary  Objects”
    //TPM2_Create()用于创建使用TPM RNG(不是那个战队，是random number generator)中的值生成的普通对象
    //TPM2_CreateLoaded()可用于创建主对象或普通对象

    //CreatePrimary创建并加载要立即使用的主对象，并提供creationData
    //在成功完成TPM响应后，将为主键创建一个新的ESYS_TR对象; ESYS_TR对象的名称用name填充
    //ESYS_TR对象的publicArea用"outPublic''填充
    //返回的handle和这个TR对象关联
    rc = Esys_CreatePrimary(esys_context, 
                            ESYS_TR_RH_OWNER,                                                       //primary handle
                            ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, 
                           ESYS_TR_NONE,
                           &inSensitivePrimary, &inPublic,                                      //inSensitive  inPublic
                           &outsideInfo, &creationPCR, &primaryHandle, 
                           &outPublic, &creationData, &creationHash,               
                           &creationTicket);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_CreatePrimary FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    //这里传入生成的ESYS_TR对象primary关联的handle来设置身份验证值authValue
    rc = Esys_TR_SetAuth(esys_context, primaryHandle, &authValuePrimary);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_TR_SetAuth FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }
    //至此父级对象Primary的创建过程完毕，接下来是它的子级loaded的创建

    //此结构用于授权值
    //使用密码来进行身份验证 ->TR_SetAuth
    //可以发现值和上面的Primary对象不一样，如果你忘了为啥可以回去看一下
    TPM2B_AUTH authKey2 = {
        .size = 6,
        .buffer = {6, 7, 8, 9, 10, 11}
    };

    //sensitive 数据
    //包括TPM2B_SENSITIVE_DATA 要密封的数据，键或派生值
    //和TPM2B_AUTH USER auth值 
    TPM2B_SENSITIVE_CREATE inSensitive2 = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0}
             },
            .data = {
                 .size = 16,
                 .buffer = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16}
             }
        }
    };

    //将授权值放入sensitive 
    inSensitive2.sensitive.userAuth = authKey2;

    //这里和上面的 inPublic作用相似
    //设置相关属性
    
    TPM2B_PUBLIC inPublic2 = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_SYMCIPHER,                                                         //对称分组密码
            .nameAlg = TPM2_ALG_SHA256,                                                        //TPMI_ALG_HASH 用于计算对象名称的算法 可为空
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |           //可以为需要USER角色授权的操作提供授权
                                 TPMA_OBJECT_SIGN_ENCRYPT |                                 // 对于对称密码对象，可以使用密钥的私有部分进行加密。
                                                                                                                                      //对于其他对象，密钥的私有部分可用于签名                                   
                                 TPMA_OBJECT_DECRYPT),                                              //私有部分可用于解密

            .authPolicy = {
                 .size = 0,
             },
            .parameters = { .symDetail = {                                                                       //对称分组密码细节
                 .sym = {
                     .algorithm = TPM2_ALG_AES,                                                       //下面各项可参照上面inPublic注释
                     .keyBits = {.aes = 128},
                     .mode = {.aes = TPM2_ALG_CFB}}
             }
             },
            .unique = {.
                sym = {
                 .size = 0,
                 .buffer = {}
                } }
        }
    };
    

    TPM2B_DATA outsideInfo2 = {
        .size = 0,
        .buffer = {}
        ,
    };

    //该结构是这里是TPM2_CreatePrimary()的输出参数，指示创建对象时在PCR状态的digest中使用的PCR
    //关于此结构体的详细信息，参阅pcr.c
    TPML_PCR_SELECTION creationPCR2 = {
        .count = 0,
    };

    TPM2B_PUBLIC *outPublic2;
    TPM2B_PRIVATE *outPrivate2;
    TPM2B_CREATION_DATA *creationData2;
    TPM2B_DIGEST *creationHash2;
    TPMT_TK_CREATION *creationTicket2;

    //此命令用于创建可以使用TPM2_Load（）加载到TPM中的对象。
    //如果命令成功完成，则TPM将创建新对象并返回该对象的创建数据（creationData），其公共区域（outPublic）和其加密的敏感区域（outPrivate）
    //在使用该对象之前，需要先将其加载 ->TPM2_Load()
    rc = Esys_Create(esys_context,
                    primaryHandle,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive2,
                    &inPublic2,
                    &outsideInfo2,
                    &creationPCR2,
                    &outPrivate2,
                    &outPublic2,
                    &creationData2, &creationHash2, &creationTicket2);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Create FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    printf("AES key created.\r\n");

    //此命令用于将对象加载到TPM中
    rc = Esys_Load(esys_context,
                  primaryHandle,                                                            //这里传入它的父对象primary的handle
                  ESYS_TR_PASSWORD,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE, outPrivate2, outPublic2, &loadedKeyHandle);

    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Create FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    printf("AES key loaded.\r\n");

    //这里传入生成的ESYS_TR对象loaded来设置身份验证值 用的authKey2
    rc = Esys_TR_SetAuth(esys_context, loadedKeyHandle, &authKey2);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_TR_SetAuth FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    ESYS_TR keyHandle_handle = loadedKeyHandle;          //这里的TR对象是Load+setAuth以后的那个      
    TPMI_YES_NO decrypt = TPM2_YES;                                     //设两个FLAG指示加密解密过程
    TPMI_YES_NO encrypt = TPM2_NO;
    TPMI_ALG_SYM_MODE mode = TPM2_ALG_NULL;         //如果密钥的模式为TPM_ALG_NULL，则可以将模式设置为任何有效的对称加密/解密模式

    //此结构用于将对称块密码的初始值传递到TPM或从TPM传递
    TPM2B_IV ivIn = {
        .size = 16,
        .buffer = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16}
    };

    //随便放点数据进去加解密
    char str[30] = {0};
    printf("\nInput data: ");
     scanf("%s", str);
     UINT16 size = strlen(str); 

    TPM2B_MAX_BUFFER inData;
    inData.size = size;
    memcpy(inData.buffer,str,size);

    printf("\ninput data ");
    HexDump2(inData.buffer, inData.size);

    TPM2B_MAX_BUFFER *outData;                                                      //加密解密结果出来就在这里
    TPM2B_IV *ivOut;

    //此命令使用keyHandle引用的对称密钥和所选模式执行对称加密或解密
    rc = Esys_EncryptDecrypt(
        esys_context,
        keyHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        encrypt,
        mode,
        &ivIn,
        &inData,
        &outData,
        &ivOut);

    if ((rc == TPM2_RC_COMMAND_CODE) ||
        (rc == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
        (rc == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        printf("Command TPM2_EncryptDecrypt not supported by TPM.");
        errorHandler(esys_context,tcti_inner,tcti_context);
    }
    
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_EncryptDecrypt FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    printf("\nencrypted data:\r\n");
    HexDump(outData->buffer, outData->size);

    TPM2B_MAX_BUFFER *outData2;                                                             //加密解密结果
    TPM2B_IV *ivOut2;

    //此命令使用keyHandle引用的对称密钥和所选模式执行对称加密或解密
    rc = Esys_EncryptDecrypt(
        esys_context,
        keyHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        decrypt,
        mode,
        &ivIn,
        outData,
        &outData2,
        &ivOut2);

    if ((rc == TPM2_RC_COMMAND_CODE) ||
        (rc == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
        (rc == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        printf("Command TPM2_EncryptDecrypt not supported by TPM.");
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_EncryptDecrypt FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    printf("\ndecrypted data ");
    HexDump2(outData2->buffer, outData2->size);
    
    if (outData2->size != inData.size ||
        memcmp(&outData2->buffer, &inData.buffer[0], outData2->size) != 0) {
        printf("Error: decrypted text not  equal to origin");
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    //FlushContext将创建的对象删除 -> primaryhandle
    rc = Esys_FlushContext(esys_context, primaryHandle);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_FlushContext FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    primaryHandle = ESYS_TR_NONE;

    //FlushContext将创建的对象删除 -> loadedKeyHandle
    rc = Esys_FlushContext(esys_context, loadedKeyHandle);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_FlushContext FAILED! Response Code : 0x%x\r\n", rc);
        errorHandler(esys_context,tcti_inner,tcti_context);
    }

    printf("\napplication done!\r\n");
    printf("clean up and quit\r\n");
    Esys_Finalize(&esys_context);
    Tss2_Tcti_Finalize  (tcti_inner);
    Tss2_Tcti_Finalize  (tcti_context);
    return 0;
}

void HexDump2(uint8_t * array, uint32_t size)
{
    printf("value:  ");
    for(uint32_t i = 0; i < size; i++){    
        printf("%c", array[i] );
    }
    printf("\r\n");
}

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
