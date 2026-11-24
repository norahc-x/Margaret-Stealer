#ifndef MARGARET_RESOLVE_H
#define MARGARET_RESOLVE_H

#include <stddef.h> /* offsetof */

#if defined(_WINDOWS_)
/* SDK first: winternl.h supplies UNICODE_STRING for the partial views. */
#include <winternl.h>

/* Not all SDK header chains define PCVOID; same type as the SDK alias. */
typedef const void *PCVOID;
#else

typedef unsigned char      BYTE;
typedef unsigned short     WORD;
typedef unsigned int       DWORD;
typedef unsigned long long ULONGLONG;
typedef int                LONG;
typedef unsigned long long SIZE_T;
typedef unsigned long long ULONG_PTR;
typedef int                BOOL;

typedef void *             PVOID;
typedef const void *       PCVOID;
typedef BYTE *             PBYTE;
typedef WORD *             PWORD;
typedef DWORD *            PDWORD;
typedef ULONGLONG *        PULONGLONG;
typedef LONG *             PLONG;

/* UTF-16 code-unit pointers; WORD-backed, not host wchar_t. */
typedef WORD *             PWSTR;
typedef const WORD *       PCWSTR;

#endif /* _WINDOWS_ */

#ifndef NULL
#define NULL  ((void *)0)
#endif
#ifndef TRUE
#define TRUE  1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#ifndef CODE_SECTION_NAME
#define CODE_SECTION_NAME ".text$M" /* Overridden per TU. */
#endif
#define CODE_SECTION   __attribute__((section(CODE_SECTION_NAME), noinline))
#define RODATA_SECTION __attribute__((section(".text$R"), used))
#define MS_ABI __attribute__((ms_abi))

_Static_assert(sizeof(BYTE) == 1, "BYTE size");
_Static_assert(sizeof(WORD) == 2, "WORD size");
_Static_assert(sizeof(DWORD) == 4, "DWORD size");
_Static_assert(sizeof(ULONGLONG) == 8, "ULONGLONG size");
_Static_assert(sizeof(LONG) == 4, "LONG size");
_Static_assert(sizeof(BOOL) == 4, "BOOL size");
_Static_assert(sizeof(void *) == 8, "Margaret requires x64 pointers");

/* Per-campaign seeded FNV-1a + DJB2 hashes; both words must match. */
#include "hash_table.h"
#define API_HASH_PRIME                16777619u

typedef struct API_HASH {
    DWORD Fnv;
    DWORD Djb;
} API_HASH;

_Static_assert(sizeof(API_HASH) == 0x08, "API_HASH pair size");
#define MAX_MODULE_WALK           128u
#define MAX_MODULE_NAME_CHARS     260u
#define MAX_EXPORT_NAMES          65536u
#define MAX_EXPORT_NAME_BYTES     512u
#define MAX_FORWARD_DEPTH         8u
#define MAX_FORWARD_VISITED       8u
#define MODULE_CACHE_CAPACITY     8u

/*
 * Fold ASCII a-z to A-Z. Hash explicit-length bytes or UTF-16 units with
 * both algorithms; UTF-16 mixes low then high byte.
 */

#if !defined(_WINDOWS_)

#define IMAGE_DOS_SIGNATURE       0x5A4Du
#define IMAGE_NT_SIGNATURE        0x00004550u
#define IMAGE_FILE_MACHINE_AMD64  0x8664u
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x020Bu
#define IMAGE_DIRECTORY_ENTRY_EXPORT  0u
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16u

typedef struct LIST_ENTRY {
    struct LIST_ENTRY *Flink;
    struct LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct UNICODE_STRING {
    WORD Length;
    WORD MaximumLength;
    BYTE AlignmentPadding[4];
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct IMAGE_DOS_HEADER {
    WORD e_magic;
    BYTE Padding0[0x3A]; /* Unviewed DOS header fields. */
    LONG e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct IMAGE_FILE_HEADER {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER;

typedef struct IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY;

typedef struct IMAGE_OPTIONAL_HEADER64 {
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    ULONGLONG ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

typedef struct IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

#endif /* !_WINDOWS_ */

/*
 * Truncated PEB/loader views. The _PARTIAL suffix marks that these are
 * not full SDK structures; only the members below are traversed.
 */
typedef struct PEB_LDR_DATA_PARTIAL {
    DWORD Length;
    BYTE Initialized;
    BYTE Padding[3];
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_PARTIAL, *PPEB_LDR_DATA_PARTIAL;

typedef struct PEB_PARTIAL {
    BYTE Padding0[0x18];
    PPEB_LDR_DATA_PARTIAL Ldr;
    BYTE Padding1[0x48]; /* 0x20 .. 0x67 */
    PVOID ApiSetMap;
} PEB_PARTIAL, *PPEB_PARTIAL;

typedef struct LDR_DATA_TABLE_ENTRY_PARTIAL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    DWORD SizeOfImage;
    BYTE AlignmentPadding[4];
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_PARTIAL, *PLDR_DATA_TABLE_ENTRY_PARTIAL;

/* Layout contracts: valid for the local views and for the x64 SDK types. */
_Static_assert(sizeof(LIST_ENTRY) == 0x10, "LIST_ENTRY x64 size");
_Static_assert(sizeof(UNICODE_STRING) == 0x10, "UNICODE_STRING x64 size");
_Static_assert(offsetof(UNICODE_STRING, Buffer) == 0x08,
               "UNICODE_STRING.Buffer x64 offset");
_Static_assert(offsetof(PEB_LDR_DATA_PARTIAL, InLoadOrderModuleList) == 0x10,
               "PEB_LDR_DATA.InLoadOrderModuleList x64 offset");
_Static_assert(offsetof(PEB_LDR_DATA_PARTIAL, InMemoryOrderModuleList) == 0x20,
               "PEB_LDR_DATA.InMemoryOrderModuleList x64 offset");
_Static_assert(offsetof(PEB_PARTIAL, Ldr) == 0x18,
               "PEB.Ldr x64 offset");
_Static_assert(offsetof(PEB_PARTIAL, ApiSetMap) == 0x68,
               "PEB.ApiSetMap x64 offset (Win11 24H2 validation point)");
_Static_assert(offsetof(LDR_DATA_TABLE_ENTRY_PARTIAL, DllBase) == 0x30,
               "LDR_DATA_TABLE_ENTRY.DllBase x64 offset");
_Static_assert(offsetof(LDR_DATA_TABLE_ENTRY_PARTIAL, SizeOfImage) == 0x40,
               "LDR_DATA_TABLE_ENTRY.SizeOfImage x64 offset");
_Static_assert(offsetof(LDR_DATA_TABLE_ENTRY_PARTIAL, FullDllName) == 0x48,
               "LDR_DATA_TABLE_ENTRY.FullDllName x64 offset");
_Static_assert(offsetof(LDR_DATA_TABLE_ENTRY_PARTIAL, BaseDllName) == 0x58,
               "LDR_DATA_TABLE_ENTRY.BaseDllName x64 offset");
_Static_assert(sizeof(IMAGE_DOS_HEADER) == 0x40, "DOS header prefix size");
_Static_assert(offsetof(IMAGE_DOS_HEADER, e_lfanew) == 0x3C,
               "DOS.e_lfanew offset");
_Static_assert(sizeof(IMAGE_FILE_HEADER) == 0x14, "COFF file header size");
_Static_assert(sizeof(IMAGE_DATA_DIRECTORY) == 0x08, "data directory size");
_Static_assert(sizeof(IMAGE_OPTIONAL_HEADER64) == 0xF0,
               "PE32+ optional header size");
_Static_assert(offsetof(IMAGE_OPTIONAL_HEADER64, ImageBase) == 0x18,
               "PE32+ ImageBase offset");
_Static_assert(offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage) == 0x38,
               "PE32+ SizeOfImage offset");
_Static_assert(offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) == 0x70,
               "PE32+ DataDirectory offset");
_Static_assert(sizeof(IMAGE_NT_HEADERS64) == 0x108, "NT headers x64 size");
_Static_assert(offsetof(IMAGE_NT_HEADERS64, OptionalHeader) == 0x18,
               "NT headers optional header offset");
_Static_assert(sizeof(IMAGE_EXPORT_DIRECTORY) == 0x28,
               "export directory size");

/*
 * API-set schema v6. resolve.c byte-reads these asserted views, matches
 * contracts through the last hyphen, and selects the first host value.
 * Importer aliases and other schema versions fail closed.
 */
#define APISET_SCHEMA_VERSION_6   6u
#define MAX_APISET_ENTRIES        512u
#define MAX_APISET_VALUES         16u
#define MAX_APISET_CONTRACT_CHARS 256u

typedef struct APISET_NAMESPACE_V6 {
    DWORD Version;       /* schema version */
    DWORD Size;          /* total schema bytes */
    DWORD Flags;
    DWORD Count;         /* namespace entries */
    DWORD EntryOffset;   /* namespace entry array */
    DWORD HashOffset;    /* sorted hash entry array */
    DWORD HashFactor;    /* polynomial hash factor */
} APISET_NAMESPACE_V6;

_Static_assert(sizeof(APISET_NAMESPACE_V6) == 0x1C,
               "api set namespace header v6 size");

typedef struct APISET_HASH_ENTRY_V6 {
    DWORD Hash;
    DWORD Index;
} APISET_HASH_ENTRY_V6;

_Static_assert(sizeof(APISET_HASH_ENTRY_V6) == 0x08,
               "api set hash entry size");

typedef struct APISET_NAMESPACE_ENTRY_V6 {
    DWORD Flags;
    DWORD NameOffset;
    DWORD NameLength;    /* bytes, includes prefix and suffix */
    DWORD HashedLength;  /* bytes of the truncation-at-last-hyphen part */
    DWORD ValueOffset;   /* value entry array */
    DWORD ValueCount;
} APISET_NAMESPACE_ENTRY_V6;

_Static_assert(sizeof(APISET_NAMESPACE_ENTRY_V6) == 0x18,
               "api set namespace entry v6 size");

typedef struct APISET_VALUE_ENTRY_V6 {
    DWORD Flags;
    DWORD NameOffset;    /* importer name; 0 length = default value */
    DWORD NameLength;
    DWORD ValueOffset;   /* host module name, UTF-16, no terminator */
    DWORD ValueLength;   /* bytes, includes the ".dll" suffix */
} APISET_VALUE_ENTRY_V6;

_Static_assert(sizeof(APISET_VALUE_ENTRY_V6) == 0x14,
               "api set value entry v6 size");

typedef enum RESOLVE_STATUS {
    ResolveStatusOk = 0,
    ResolveStatusBadArgument = 1,
    ResolveStatusNoPeb = 2,
    ResolveStatusNoLdr = 3,
    ResolveStatusModuleNotFound = 4,
    ResolveStatusBadImage = 5,
    ResolveStatusExportNotFound = 6,
    ResolveStatusOrdinalOutOfRange = 7,
    ResolveStatusForwardDepth = 8,
    ResolveStatusForwardCycle = 9,
    ResolveStatusApiSetUnsupported = 10,
    ResolveStatusBoundExceeded = 11,
    ResolveStatusNotImplemented = 12
} RESOLVE_STATUS;

typedef struct MODULE_CACHE_ENTRY {
    API_HASH NameHash;
    DWORD ImageSize;
    PVOID Base;
} MODULE_CACHE_ENTRY;

/* Project API table; currently empty. */
typedef struct API_TABLE {
    DWORD Version;
    DWORD ResolvedCount;
} API_TABLE;

typedef struct RESOLVER_CONTEXT {
    const BYTE *BlobAnchor;
    DWORD BlobSize;
    DWORD Status;
    DWORD LastError;
    DWORD ShutdownReason;
    PVOID ArgumentBlock;
    API_TABLE Api;
    MODULE_CACHE_ENTRY Modules[MODULE_CACHE_CAPACITY];

    /* Active forwarder chain used for bounded cycle detection. */
    DWORD ForwardDepth;
    DWORD ForwardVisitedCount;
    API_HASH ForwardVisited[MAX_FORWARD_VISITED];
} RESOLVER_CONTEXT;

PPEB_PARTIAL MS_ABI CurrentPeb(void);
void MS_ABI HashAsciiUpper(const BYTE *data, DWORD length,
                                    API_HASH *out);
void MS_ABI HashUtf16Upper(PCWSTR data, DWORD codeUnits,
                                    API_HASH *out);
RESOLVE_STATUS MS_ABI FindModule(RESOLVER_CONTEXT *ctx,
                                          const API_HASH *moduleHash,
                                          PVOID *moduleBase);
RESOLVE_STATUS MS_ABI ResolveExport(RESOLVER_CONTEXT *ctx,
                                             PVOID moduleBase,
                                             const API_HASH *exportHash,
                                             PVOID *address);
RESOLVE_STATUS MS_ABI ResolveOrdinal(RESOLVER_CONTEXT *ctx,
                                              PVOID moduleBase,
                                              WORD ordinal,
                                              PVOID *address);
RESOLVE_STATUS MS_ABI ResolveForwarder(RESOLVER_CONTEXT *ctx,
                                                const char *forwarder,
                                                DWORD forwarderLength,
                                                DWORD depth,
                                                PVOID *address);
RESOLVE_STATUS MS_ABI ResolveApiSetContract(RESOLVER_CONTEXT *ctx,
                                                     PCWSTR contract,
                                                     DWORD contractCodeUnits,
                                                     PVOID *moduleBase);

#endif /* MARGARET_RESOLVE_H */
