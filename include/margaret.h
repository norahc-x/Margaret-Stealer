#ifndef MARGARET_H
#define MARGARET_H

#include "resolve.h"

#define MARGARET_ARGUMENT_MAGIC 0x4752414Du /* "MARG" little-endian */
#define MARGARET_RESULT_MAGIC   0x544C5352u /* "RSLT" little-endian */
#define MARGARET_ABI_VERSION    1u

/* Entry ABI: CALL with RSP % 16 == 8; RCX=args, RAX=status. */
#define MARGARET_ARCH_X64       0x8664u

typedef enum MARGARET_OPERATION {
    MargaretOperationNone = 0,
    MargaretOperationPing = 1,
    MargaretOperationSnapshotDefaultProfile = 2,
    MargaretOperationSnapshotBrowser = 3
} MARGARET_OPERATION;

typedef enum MARGARET_STATUS {
    MargaretStatusOk = 0,
    MargaretStatusBadArgument = 1,
    MargaretStatusBadMagic = 2,
    MargaretStatusBadVersion = 3,
    MargaretStatusBufferTooSmall = 4,
    MargaretStatusUnsupportedOperation = 5,
    MargaretStatusUnsupportedBuild = 6,
    MargaretStatusInternalError = 7
} MARGARET_STATUS;

typedef struct MARGARET_ARGS {
    DWORD Size;
    DWORD Version;
    DWORD Magic;
    DWORD Operation;
    PVOID OutputBuffer;
    DWORD OutputCapacity;
    DWORD OutputLength;
    DWORD Status;
    DWORD TimeoutMs;
    DWORD Flags;
    DWORD Pad; /* Calibration stage. */
} MARGARET_ARGS;

_Static_assert(sizeof(MARGARET_ARGS) == 0x30, "MARGARET_ARGS x64 ABI size");
_Static_assert(offsetof(MARGARET_ARGS, Size) == 0x00,
               "MARGARET_ARGS size offset");
_Static_assert(offsetof(MARGARET_ARGS, Version) == 0x04,
               "MARGARET_ARGS version offset");
_Static_assert(offsetof(MARGARET_ARGS, Magic) == 0x08,
               "MARGARET_ARGS magic offset");
_Static_assert(offsetof(MARGARET_ARGS, Operation) == 0x0C,
               "MARGARET_ARGS operation offset");
_Static_assert(offsetof(MARGARET_ARGS, OutputBuffer) == 0x10,
               "MARGARET_ARGS output pointer offset");
_Static_assert(offsetof(MARGARET_ARGS, OutputCapacity) == 0x18,
               "MARGARET_ARGS output capacity offset");
_Static_assert(offsetof(MARGARET_ARGS, OutputLength) == 0x1C,
               "MARGARET_ARGS output length offset");
_Static_assert(offsetof(MARGARET_ARGS, Status) == 0x20,
               "MARGARET_ARGS status offset");
_Static_assert(offsetof(MARGARET_ARGS, TimeoutMs) == 0x24,
               "MARGARET_ARGS timeout offset");
_Static_assert(offsetof(MARGARET_ARGS, Flags) == 0x28,
               "MARGARET_ARGS flags offset");

typedef struct MARGARET_RESULT_HEADER {
    DWORD Magic;
    DWORD Version;
    DWORD Status;
    DWORD PayloadLength;
} MARGARET_RESULT_HEADER;

_Static_assert(sizeof(MARGARET_RESULT_HEADER) == 0x10,
               "result header ABI size");

typedef struct MARGARET_PING_RESULT {
    MARGARET_RESULT_HEADER Header;
    DWORD Architecture;
    DWORD BlobSize;
    DWORD AbiVersion;
    DWORD Reserved;
} MARGARET_PING_RESULT;

_Static_assert(sizeof(MARGARET_PING_RESULT) == 0x20,
               "ping result ABI size");

/* Adapter-selection diagnostic. */
typedef struct MARGARET_ADAPTER_RESULT {
    MARGARET_RESULT_HEADER Header;
    DWORD AdapterVersion;
    DWORD ImageSize;
    DWORD RvaCookieMonsterVtable;
    DWORD RvaCookieMonsterGetAllCookies;
} MARGARET_ADAPTER_RESULT;

_Static_assert(sizeof(MARGARET_ADAPTER_RESULT) == 0x20,
               "adapter result ABI size");

/*
 * Snapshot: magic, cookie/instance counts, scan addresses, reserved word,
 * then length-prefixed name/domain/path/value plus creation, expiry, flags,
 * same-site, and port.
 */
#define MARGARET_ENGINE_A_MAGIC 0x4145434Du /* "MCEA" little-endian */


/* Vtable-anchored CookieMonster snapshot. */
struct MARGARET_CHROMIUM_ADAPTER;
DWORD MS_ABI MargaretEngineASnapshot(
    RESOLVER_CONTEXT *ctx,
    const struct MARGARET_CHROMIUM_ADAPTER *adapter,
    MARGARET_ARGS *args);

/* ABI symbol pair with asm/entry_x64.s; keep the entry-ABI names. */
PVOID MS_ABI MargaretMemzero(PVOID buffer, SIZE_T length);
PVOID MS_ABI MargaretMemcpy(PVOID destination, PCVOID source,
                                     SIZE_T length);
DWORD MS_ABI margaret_main(MARGARET_ARGS *args,
                                    const BYTE *blobAnchor,
                                    DWORD blobSize);

#endif /* MARGARET_H */
