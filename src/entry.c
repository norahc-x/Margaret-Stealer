#define CODE_SECTION_NAME ".text$B"
#include "margaret.h"
#include "chromium_adapter.h"

static CODE_SECTION DWORD WritePingResult(MARGARET_ARGS *args,
                                           DWORD blobSize)
{
    MARGARET_PING_RESULT *result;

    if (args->OutputBuffer == NULL ||
        args->OutputCapacity < (DWORD)sizeof(MARGARET_PING_RESULT)) {
        args->OutputLength = (DWORD)sizeof(MARGARET_PING_RESULT);
        args->Status = (DWORD)MargaretStatusBufferTooSmall;
        return (DWORD)MargaretStatusBufferTooSmall;
    }

    result = (MARGARET_PING_RESULT *)args->OutputBuffer;
    result->Header.Magic = MARGARET_RESULT_MAGIC;
    result->Header.Version = MARGARET_ABI_VERSION;
    result->Header.Status = (DWORD)MargaretStatusOk;
    result->Header.PayloadLength =
        (DWORD)(sizeof(MARGARET_PING_RESULT) - sizeof(MARGARET_RESULT_HEADER));
    result->Architecture = MARGARET_ARCH_X64;
    result->BlobSize = blobSize;
    result->AbiVersion = MARGARET_ABI_VERSION;
    result->Reserved = 0u;

    args->OutputLength = (DWORD)sizeof(MARGARET_PING_RESULT);
    args->Status = (DWORD)MargaretStatusOk;
    return (DWORD)MargaretStatusOk;
}


CODE_SECTION DWORD MS_ABI margaret_main(MARGARET_ARGS *args,
                                           const BYTE *blobAnchor,
                                           DWORD blobSize)
{
    RESOLVER_CONTEXT context;
    DWORD status;

    if (args == NULL || blobAnchor == NULL) {
        return (DWORD)MargaretStatusBadArgument;
    }

    if (args->Size < (DWORD)sizeof(MARGARET_ARGS)) {
        return (DWORD)MargaretStatusBadArgument;
    }

    if (args->Magic != MARGARET_ARGUMENT_MAGIC) {
        args->Status = (DWORD)MargaretStatusBadMagic;
        return (DWORD)MargaretStatusBadMagic;
    }
    if (args->Version != MARGARET_ABI_VERSION) {
        args->Status = (DWORD)MargaretStatusBadVersion;
        return (DWORD)MargaretStatusBadVersion;
    }

    if (blobSize == 0u) {
        args->Status = (DWORD)MargaretStatusInternalError;
        return (DWORD)MargaretStatusInternalError;
    }

    (void)MargaretMemzero(&context, (SIZE_T)sizeof(context));
    context.BlobAnchor = blobAnchor;
    context.BlobSize = blobSize;
    context.ArgumentBlock = args;
    context.Api.Version = MARGARET_ABI_VERSION;

    switch ((MARGARET_OPERATION)args->Operation) {
    case MargaretOperationPing:
        status = WritePingResult(args, blobSize);
        break;
    case MargaretOperationSnapshotDefaultProfile: {
        PVOID chromeBase;
        DWORD imageSize;
        MARGARET_CHROMIUM_ADAPTER adapter;
        args->Flags = 10u; /* Dispatch entered. */
        if (MargaretLocateChromeDll(&context, &chromeBase, &imageSize) !=
            FALSE) {
            args->Flags = 11u; /* Module located. */
            if (MargaretSelectChromiumAdapter(chromeBase, imageSize,
                                                 &adapter) != FALSE) {
                args->Flags = 12u; /* Adapter selected. */
                status = MargaretEngineASnapshot(&context, &adapter, args);
            } else {
                args->Status = (DWORD)MargaretStatusUnsupportedBuild;
                status = (DWORD)MargaretStatusUnsupportedBuild;
            }
        } else {
            args->Status = (DWORD)MargaretStatusUnsupportedBuild;
            status = (DWORD)MargaretStatusUnsupportedBuild;
        }
        (void)MargaretMemzero(&adapter, sizeof(adapter));
        break;
    }
    case MargaretOperationNone:
    default:
        args->Status = (DWORD)MargaretStatusUnsupportedOperation;
        status = (DWORD)MargaretStatusUnsupportedOperation;
        break;
    }

    context.Status = status;
    (void)MargaretMemzero(&context, (SIZE_T)sizeof(context));
    return status;
}