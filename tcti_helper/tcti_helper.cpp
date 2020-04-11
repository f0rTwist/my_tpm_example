/*Include section*************************************************************/
//not sure if we need all
#include "tcti_helper.h"

/*Define section**************************************************************/
#define TCTI_PROXY_MAGIC 0x5250584f0a000000ULL /* 'PROXY\0\0\0' */
#define TCTI_PROXY_VERSION 0x1

#define TCTI_MSSIM_CONF_MAX 30
#define TCTI_MSSIM

/*Variable********************************************************************/
TSS2_RC
(*transmit_hook) (const uint8_t *command_buffer, size_t command_size) = NULL;


uint8_t yielded_response[] = {
    0x80, 0x01,             /* TPM_ST_NO_SESSION */
    0x00, 0x00, 0x00, 0x0A, /* Response Size 10 */
    0x00, 0x00, 0x09, 0x08  /* TPM_RC_YIELDED */
};



/*****************************************************************************/
TSS2_TCTI_CONTEXT_PROXY*
tcti_proxy_cast (TSS2_TCTI_CONTEXT *ctx)
{
    TSS2_TCTI_CONTEXT_PROXY *ctxi = (TSS2_TCTI_CONTEXT_PROXY*)ctx;
    if (ctxi == NULL || ctxi->magic != TCTI_PROXY_MAGIC) {
        printf("Bad tcti passed.");
        return NULL;
    }
    return ctxi;
}


TSS2_RC
tcti_proxy_transmit(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t command_size,
    const uint8_t *command_buffer
    )
{
    TSS2_RC rval;
    TSS2_TCTI_CONTEXT_PROXY *tcti_proxy = tcti_proxy_cast(tctiContext);

    if (tcti_proxy->state == intercepting) {
        return TSS2_RC_SUCCESS;
    }

    if (transmit_hook != NULL) {
        rval = transmit_hook(command_buffer, command_size);
        if (rval != TSS2_RC_SUCCESS) {
            printf("transmit hook requested error");
            return rval;
        }
    }

    rval = Tss2_Tcti_Transmit(tcti_proxy->tctiInner, command_size,
        command_buffer);
    if (rval != TSS2_RC_SUCCESS) {
        printf("Calling TCTI Transmit");
        return rval;
    }

    return rval;
}

TSS2_RC
tcti_proxy_receive(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    uint8_t *response_buffer,
    int32_t timeout
    )
{
    TSS2_RC rval;
    TSS2_TCTI_CONTEXT_PROXY *tcti_proxy = tcti_proxy_cast(tctiContext);

    if (tcti_proxy->state == intercepting) {
        *response_size = sizeof(yielded_response);

        if (response_buffer != NULL) {
            memcpy(response_buffer, &yielded_response[0], sizeof(yielded_response));
            tcti_proxy->state = forwarding;
        }
        return TSS2_RC_SUCCESS;
    }

    rval = Tss2_Tcti_Receive(tcti_proxy->tctiInner, response_size,
                             response_buffer, timeout);
    if (rval != TSS2_RC_SUCCESS) {
        printf("Calling TCTI Transmit");
        return rval;
    }

    /* First read with response buffer == NULL is to get the size of the
     * response. The subsequent read needs to be forwarded also */
    if (response_buffer != NULL)
        tcti_proxy->state = intercepting;

    return rval;
}

void
tcti_proxy_finalize(
    TSS2_TCTI_CONTEXT *tctiContext)
{
    memset(tctiContext, 0, sizeof(TSS2_TCTI_CONTEXT_PROXY));
}

TSS2_RC
tcti_proxy_initialize(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *contextSize,
    TSS2_TCTI_CONTEXT *tctiInner)
{
    TSS2_TCTI_CONTEXT_PROXY *tcti_proxy =
        (TSS2_TCTI_CONTEXT_PROXY*) tctiContext;

    if (tctiContext == NULL && contextSize == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *contextSize = sizeof(*tcti_proxy);
        return TSS2_RC_SUCCESS;
    }

    /* Init TCTI context */
    memset(tcti_proxy, 0, sizeof(*tcti_proxy));
    TSS2_TCTI_MAGIC (tctiContext) = TCTI_PROXY_MAGIC;
    TSS2_TCTI_VERSION (tctiContext) = TCTI_PROXY_VERSION;
    TSS2_TCTI_TRANSMIT (tctiContext) = tcti_proxy_transmit;
    TSS2_TCTI_RECEIVE (tctiContext) = tcti_proxy_receive;
    TSS2_TCTI_FINALIZE (tctiContext) = tcti_proxy_finalize;
    TSS2_TCTI_CANCEL (tctiContext) = NULL;
    TSS2_TCTI_GET_POLL_HANDLES (tctiContext) = NULL;
    TSS2_TCTI_SET_LOCALITY (tctiContext) = NULL;
    tcti_proxy->tctiInner = tctiInner;
    tcti_proxy->state = forwarding;

    return TSS2_RC_SUCCESS;
}

TSS2_TCTI_CONTEXT *
tcti_init_from_opts(test_opts_t * options)
{
    switch (options->tcti_type) {
#ifdef TCTI_DEVICE
    case DEVICE_TCTI:
        return tcti_device_init(options->device_file);
#endif /* TCTI_DEVICE */
#ifdef TCTI_MSSIM
    case SOCKET_TCTI:
        return tcti_socket_init(options->socket_address, options->socket_port);
#endif /* TCTI_MSSIM */
#ifdef TCTI_FUZZING
    case FUZZING_TCTI:
        return tcti_fuzzing_init();
#endif /* TCTI_FUZZING */
    default:
        return NULL;
    }
}

TSS2_TCTI_CONTEXT *
tcti_socket_init(char const *host, uint16_t port)
{
    size_t size;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx;
    char conf_str[TCTI_MSSIM_CONF_MAX] = { 0 };

    snprintf(conf_str, TCTI_MSSIM_CONF_MAX, "host=%s,port=%" PRIu16, host, port);
    rc = Tss2_Tcti_Mssim_Init(NULL, &size, conf_str);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Faled to get allocation size for tcti context: 0x%x\n", rc);
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc(1, size);
    if (tcti_ctx == NULL) {
        printf("Allocation for tcti context failed:\n");
        return NULL;
    }
    rc = Tss2_Tcti_Mssim_Init(tcti_ctx, &size, conf_str);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Failed to initialize tcti context: 0x%x\n", rc);
        free(tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}
