#ifndef MARGARET_PIC_RESOLVE_H
#define MARGARET_PIC_RESOLVE_H

/*
 * Margaret x64 PIC resolution contract.
 *
 * The structures below contain only fields consumed by this project.  Public
 * PE/COFF definitions are mirrored from the Microsoft PE/COFF specification.
 * The x64 TEB/PEB/loader offsets follow the public structure prefixes and the
 * Windows 11 24H2 x64 validation points below.  Runtime compatibility across a
 * wider Windows 10/11 matrix remains unverified in milestone 1.
 * Sources:
 *   https://learn.microsoft.com/windows/win32/api/winternl/ns-winternl-peb
 *   https://learn.microsoft.com/windows/win32/api/winternl/ns-winternl-peb_ldr_data
 *   https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_TEB
 *   https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_PEB
 * TEB->ProcessEnvironmentBlock is read from GS:[0x60] on x64.  This segment
 * offset cannot be expressed as a C member assertion and is isolated in
 * pic_current_peb().  All offsets must be revalidated if the support matrix
 * changes.
 */

typedef unsigned char      pic_u8;
typedef unsigned short     pic_u16;
typedef unsigned int       pic_u32;
typedef unsigned long long pic_u64;
typedef signed int         pic_i32;
typedef unsigned long long pic_size;
typedef unsigned long long pic_uptr;
typedef int                pic_bool;

#define PIC_TRUE  1
#define PIC_FALSE 0
#define PIC_NULL  ((void *)0)

#define PIC_OFFSETOF(type, member) __builtin_offsetof(type, member)
#define PIC_STATIC_ASSERT(expr, message) _Static_assert((expr), message)

#ifndef PIC_CODE_SECTION_NAME
#define PIC_CODE_SECTION_NAME ".text$M"
#endif
#define PIC_CODE   __attribute__((section(PIC_CODE_SECTION_NAME), noinline))
#define PIC_RODATA __attribute__((section(".text$R"), used))
#define PIC_MS_ABI __attribute__((ms_abi))

PIC_STATIC_ASSERT(sizeof(pic_u8) == 1, "pic_u8 size");
PIC_STATIC_ASSERT(sizeof(pic_u16) == 2, "pic_u16 size");
PIC_STATIC_ASSERT(sizeof(pic_u32) == 4, "pic_u32 size");
PIC_STATIC_ASSERT(sizeof(pic_u64) == 8, "pic_u64 size");
PIC_STATIC_ASSERT(sizeof(void *) == 8, "Margaret requires x64 pointers");

/* Resolver policy.  Dual-32 API hashing: seeded FNV-1a + seeded DJB2
 * computed in one pass; a name matches only when both words match
 * (effective 64-bit discrimination, imm32-only constants — no movabs).
 * Seeds are per-campaign, generated into pic_hash_table.h by
 * scripts/hash.py from scripts/hash_seed. */
#include "pic_hash_table.h"
#define PIC_HASH_PRIME                16777619u

typedef struct PIC_HASH {
    pic_u32 fnv;
    pic_u32 djb;
} PIC_HASH;

PIC_STATIC_ASSERT(sizeof(PIC_HASH) == 0x08, "PIC_HASH pair size");
#define PIC_MAX_MODULE_WALK           128u
#define PIC_MAX_MODULE_NAME_CHARS     260u
#define PIC_MAX_EXPORT_NAMES          65536u
#define PIC_MAX_EXPORT_NAME_BYTES     512u
#define PIC_MAX_FORWARD_DEPTH         8u
#define PIC_MAX_FORWARD_VISITED       8u
#define PIC_MODULE_CACHE_CAPACITY     8u

/* Hash rules:
 * - Dual 32-bit: FNV-1a (xor-multiply) and DJB2 ((h<<5)+h+b) per byte.
 * - ASCII a-z are folded to A-Z before mixing.
 * - UTF-16 module names hash one 16-bit code unit at a time after ASCII
 *   fold; each unit mixes its low byte then high byte through both words.
 * - Input length is always explicit and bounded; no implicit unbounded
 *   scan.  Hashes are written to a caller PIC_HASH (no return-by-value).
 */

#define PIC_IMAGE_DOS_SIGNATURE       0x5A4Du
#define PIC_IMAGE_NT_SIGNATURE        0x00004550u
#define PIC_IMAGE_FILE_MACHINE_AMD64  0x8664u
#define PIC_IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x020Bu
#define PIC_IMAGE_DIRECTORY_ENTRY_EXPORT  0u
#define PIC_IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16u

typedef struct PIC_LIST_ENTRY {
    struct PIC_LIST_ENTRY *Flink;
    struct PIC_LIST_ENTRY *Blink;
} PIC_LIST_ENTRY;

PIC_STATIC_ASSERT(sizeof(PIC_LIST_ENTRY) == 0x10, "LIST_ENTRY x64 size");

typedef struct PIC_UNICODE_STRING {
    pic_u16 Length;
    pic_u16 MaximumLength;
    pic_u32 Reserved;
    pic_u16 *Buffer;
} PIC_UNICODE_STRING;

PIC_STATIC_ASSERT(sizeof(PIC_UNICODE_STRING) == 0x10, "UNICODE_STRING x64 size");
PIC_STATIC_ASSERT(PIC_OFFSETOF(PIC_UNICODE_STRING, Buffer) == 0x08,
                  "UNICODE_STRING.Buffer x64 offset");

typedef struct PIC_PEB_LDR_DATA {
    pic_u32 Length;
    pic_u8 Initialized;
    pic_u8 Reserved1[3];
    void *SsHandle;
    PIC_LIST_ENTRY InLoadOrderModuleList;
    PIC_LIST_ENTRY InMemoryOrderModuleList;
    PIC_LIST_ENTRY InInitializationOrderModuleList;
} PIC_PEB_LDR_DATA;

PIC_STATIC_ASSERT(PIC_OFFSETOF(PIC_PEB_LDR_DATA, InLoadOrderModuleList) == 0x10,
                  "PEB_LDR_DATA.InLoadOrderModuleList x64 offset");
PIC_STATIC_ASSERT(PIC_OFFSETOF(PIC_PEB_LDR_DATA, InMemoryOrderModuleList) == 0x20,
                  "PEB_LDR_DATA.InMemoryOrderModuleList x64 offset");

typedef struct PIC_PEB {
    pic_u8 Reserved0[0x18];
    PIC_PEB_LDR_DATA *Ldr;
    pic_u8 Reserved1[0x48]; /* 0x20 .. 0x67 */
    void *ApiSetMap;
} PIC_PEB;

PIC_STATIC_ASSERT(PIC_OFFSETOF(PIC_PEB, Ldr) == 0x18,
                  "PEB.Ldr x64 offset");
PIC_STATIC_ASSERT(PIC_OFFSETOF(PIC_PEB, ApiSetMap) == 0x68,
                  "PEB.ApiSetMap x64 offset (Win11 24H2 validation point)");

typedef struct PIC_LDR_DATA_TABLE_ENTRY {
    PIC_LIST_ENTRY InLoadOrderLinks;
    PIC_LIST_ENTRY InMemoryOrderLinks;
    PIC_LIST_ENTRY InInitializationOrderLinks;
    void *DllBase;
    void *EntryPoint;
    pic_u32 SizeOfImage;
    pic_u32 Reserved0;
    PIC_UNICODE_STRING FullDllName;
    PIC_UNICODE_STRING BaseDllName;
} PIC_LDR_DATA_TABLE_ENTRY;

PIC_STATIC_ASSERT(PIC_OFFSETOF(PIC_LDR_DATA_TABLE_ENTRY, DllBase) == 0x30,
                  "LDR_DATA_TABLE_ENTRY.DllBase x64 offset");
PIC_STATIC_ASSERT(PIC_OFFSETOF(PIC_LDR_DATA_TABLE_ENTRY, SizeOfImage) == 0x40,
                  "LDR_DATA_TABLE_ENTRY.SizeOfImage x64 offset");
PIC_STATIC_ASSERT(PIC_OFFSETOF(PIC_LDR_DATA_TABLE_ENTRY, FullDllName) == 0x48,
                  "LDR_DATA_TABLE_ENTRY.FullDllName x64 offset");
PIC_STATIC_ASSERT(PIC_OFFSETOF(PIC_LDR_DATA_TABLE_ENTRY, BaseDllName) == 0x58,
                  "LDR_DATA_TABLE_ENTRY.BaseDllName x64 offset");

typedef struct PIC_IMAGE_DOS_HEADER {
    pic_u16 e_magic;
    pic_u8 Reserved0[0x3A];
    pic_i32 e_lfanew;
} PIC_IMAGE_DOS_HEADER;

PIC_STATIC_ASSERT(sizeof(PIC_IMAGE_DOS_HEADER) == 0x40, "DOS header prefix size");
PIC_STATIC_ASSERT(PIC_OFFSETOF(PIC_IMAGE_DOS_HEADER, e_lfanew) == 0x3C,
                  "DOS.e_lfanew offset");

typedef struct PIC_IMAGE_FILE_HEADER {
    pic_u16 Machine;
    pic_u16 NumberOfSections;
    pic_u32 TimeDateStamp;
    pic_u32 PointerToSymbolTable;
    pic_u32 NumberOfSymbols;
    pic_u16 SizeOfOptionalHeader;
    pic_u16 Characteristics;
} PIC_IMAGE_FILE_HEADER;

PIC_STATIC_ASSERT(sizeof(PIC_IMAGE_FILE_HEADER) == 0x14, "COFF file header size");

typedef struct PIC_IMAGE_DATA_DIRECTORY {
    pic_u32 VirtualAddress;
    pic_u32 Size;
} PIC_IMAGE_DATA_DIRECTORY;

PIC_STATIC_ASSERT(sizeof(PIC_IMAGE_DATA_DIRECTORY) == 0x08, "data directory size");

typedef struct PIC_IMAGE_OPTIONAL_HEADER64 {
    pic_u16 Magic;
    pic_u8 MajorLinkerVersion;
    pic_u8 MinorLinkerVersion;
    pic_u32 SizeOfCode;
    pic_u32 SizeOfInitializedData;
    pic_u32 SizeOfUninitializedData;
    pic_u32 AddressOfEntryPoint;
    pic_u32 BaseOfCode;
    pic_u64 ImageBase;
    pic_u32 SectionAlignment;
    pic_u32 FileAlignment;
    pic_u16 MajorOperatingSystemVersion;
    pic_u16 MinorOperatingSystemVersion;
    pic_u16 MajorImageVersion;
    pic_u16 MinorImageVersion;
    pic_u16 MajorSubsystemVersion;
    pic_u16 MinorSubsystemVersion;
    pic_u32 Win32VersionValue;
    pic_u32 SizeOfImage;
    pic_u32 SizeOfHeaders;
    pic_u32 CheckSum;
    pic_u16 Subsystem;
    pic_u16 DllCharacteristics;
    pic_u64 SizeOfStackReserve;
    pic_u64 SizeOfStackCommit;
    pic_u64 SizeOfHeapReserve;
    pic_u64 SizeOfHeapCommit;
    pic_u32 LoaderFlags;
    pic_u32 NumberOfRvaAndSizes;
    PIC_IMAGE_DATA_DIRECTORY DataDirectory[PIC_IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} PIC_IMAGE_OPTIONAL_HEADER64;

PIC_STATIC_ASSERT(sizeof(PIC_IMAGE_OPTIONAL_HEADER64) == 0xF0,
                  "PE32+ optional header size");
PIC_STATIC_ASSERT(PIC_OFFSETOF(PIC_IMAGE_OPTIONAL_HEADER64, ImageBase) == 0x18,
                  "PE32+ ImageBase offset");
PIC_STATIC_ASSERT(PIC_OFFSETOF(PIC_IMAGE_OPTIONAL_HEADER64, SizeOfImage) == 0x38,
                  "PE32+ SizeOfImage offset");
PIC_STATIC_ASSERT(PIC_OFFSETOF(PIC_IMAGE_OPTIONAL_HEADER64, DataDirectory) == 0x70,
                  "PE32+ DataDirectory offset");

typedef struct PIC_IMAGE_NT_HEADERS64 {
    pic_u32 Signature;
    PIC_IMAGE_FILE_HEADER FileHeader;
    PIC_IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} PIC_IMAGE_NT_HEADERS64;

PIC_STATIC_ASSERT(sizeof(PIC_IMAGE_NT_HEADERS64) == 0x108, "NT headers x64 size");
PIC_STATIC_ASSERT(PIC_OFFSETOF(PIC_IMAGE_NT_HEADERS64, OptionalHeader) == 0x18,
                  "NT headers optional header offset");

typedef struct PIC_IMAGE_EXPORT_DIRECTORY {
    pic_u32 Characteristics;
    pic_u32 TimeDateStamp;
    pic_u16 MajorVersion;
    pic_u16 MinorVersion;
    pic_u32 Name;
    pic_u32 Base;
    pic_u32 NumberOfFunctions;
    pic_u32 NumberOfNames;
    pic_u32 AddressOfFunctions;
    pic_u32 AddressOfNames;
    pic_u32 AddressOfNameOrdinals;
} PIC_IMAGE_EXPORT_DIRECTORY;

PIC_STATIC_ASSERT(sizeof(PIC_IMAGE_EXPORT_DIRECTORY) == 0x28,
                  "export directory size");

/*
 * API-set schema view (PEB->ApiSetMap), version 6 (Windows 10 1607
 * through Windows 11).  Layout constants follow zodiacon's
 * WindowsInternals ApiSet.h; lookup semantics follow the reversed ntdll
 * functions ApiSetpSearchForApiSet / ApiSetResolveToHost (lucasg's
 * apiset-lookup gist), cross-checked against ColinFinck/nt-apiset.
 *
 * These declarations exist for the asserted SIZEOF/OFFSETOF constants
 * only: resolve.c reads every field byte-wise because schema bytes are
 * not guaranteed to be aligned and schema strings are not NUL-terminated.
 *
 * Loader rules implemented in resolve.c:
 * - contract names must start with "api-" or "ext-" (case-insensitive);
 * - matching uses the name truncated at the last hyphen;
 * - the default (first) value entry is the host; importer-name value
 *   aliasing is deliberately not implemented;
 * - the schema hash table is not used: entries are linearly scanned with
 *   the same truncated-name comparison the loader applies after its
 *   hash-table probe.
 *
 * Version gate: any schema version != 6 fails closed with
 * PIC_RESOLVE_APISET_UNSUPPORTED.  Validated against the Windows 11 24H2
 * x64 matrix only.
 */
#define PIC_APISET_SCHEMA_VERSION_6   6u
#define PIC_MAX_APISET_ENTRIES        512u
#define PIC_MAX_APISET_VALUES         16u
#define PIC_MAX_APISET_CONTRACT_CHARS 256u

typedef struct PIC_APISET_NAMESPACE {
    pic_u32 version;       /* schema version */
    pic_u32 size;          /* total schema bytes */
    pic_u32 flags;
    pic_u32 count;         /* namespace entries */
    pic_u32 entry_offset;  /* namespace entry array */
    pic_u32 hash_offset;   /* sorted hash entry array */
    pic_u32 hash_factor;   /* polynomial hash factor */
} PIC_APISET_NAMESPACE;

PIC_STATIC_ASSERT(sizeof(PIC_APISET_NAMESPACE) == 0x1C,
                  "api set namespace header v6 size");

typedef struct PIC_APISET_HASH_ENTRY {
    pic_u32 hash;
    pic_u32 index;
} PIC_APISET_HASH_ENTRY;

PIC_STATIC_ASSERT(sizeof(PIC_APISET_HASH_ENTRY) == 0x08,
                  "api set hash entry size");

typedef struct PIC_APISET_NAMESPACE_ENTRY {
    pic_u32 flags;
    pic_u32 name_offset;
    pic_u32 name_length;   /* bytes, includes prefix and suffix */
    pic_u32 hashed_length; /* bytes of the truncation-at-last-hyphen part */
    pic_u32 value_offset;  /* value entry array */
    pic_u32 value_count;
} PIC_APISET_NAMESPACE_ENTRY;

PIC_STATIC_ASSERT(sizeof(PIC_APISET_NAMESPACE_ENTRY) == 0x18,
                  "api set namespace entry v6 size");

typedef struct PIC_APISET_VALUE_ENTRY {
    pic_u32 flags;
    pic_u32 name_offset;   /* importer name; 0 length = default value */
    pic_u32 name_length;
    pic_u32 value_offset;  /* host module name, UTF-16, no terminator */
    pic_u32 value_length;  /* bytes, includes the ".dll" suffix */
} PIC_APISET_VALUE_ENTRY;

PIC_STATIC_ASSERT(sizeof(PIC_APISET_VALUE_ENTRY) == 0x14,
                  "api set value entry v6 size");

typedef enum PIC_RESOLVE_STATUS {
    PIC_RESOLVE_OK = 0,
    PIC_RESOLVE_BAD_ARGUMENT = 1,
    PIC_RESOLVE_NO_PEB = 2,
    PIC_RESOLVE_NO_LDR = 3,
    PIC_RESOLVE_MODULE_NOT_FOUND = 4,
    PIC_RESOLVE_BAD_IMAGE = 5,
    PIC_RESOLVE_EXPORT_NOT_FOUND = 6,
    PIC_RESOLVE_ORDINAL_OUT_OF_RANGE = 7,
    PIC_RESOLVE_FORWARD_DEPTH = 8,
    PIC_RESOLVE_FORWARD_CYCLE = 9,
    PIC_RESOLVE_APISET_UNSUPPORTED = 10,
    PIC_RESOLVE_BOUND_EXCEEDED = 11,
    PIC_RESOLVE_NOT_IMPLEMENTED = 12
} PIC_RESOLVE_STATUS;

typedef struct PIC_MODULE_CACHE_ENTRY {
    PIC_HASH name_hash;
    pic_u32 image_size;
    void *base;
} PIC_MODULE_CACHE_ENTRY;

/* No Windows APIs are resolved by the milestone-1 shellcode.  New typed
 * function pointers are added here only when a later feature actually needs
 * them. */
typedef struct PIC_API_TABLE {
    pic_u32 version;
    pic_u32 resolved_count;
} PIC_API_TABLE;

typedef struct PIC_CONTEXT {
    const pic_u8 *blob_anchor;
    pic_u32 blob_size;
    pic_u32 status;
    pic_u32 last_error;
    pic_u32 shutdown_reason;
    void *argument_block;
    PIC_API_TABLE api;
    PIC_MODULE_CACHE_ENTRY modules[PIC_MODULE_CACHE_CAPACITY];

    /* Transient forwarded-export state.  Zeroed with the context; consumed
     * only by the resolver.  forward_visited stores dual-32 hashes of the
     * forwarder strings on the active chain, so a repeat is a cycle.  A
     * hash collision can only produce a spurious (fail-closed)
     * PIC_RESOLVE_FORWARD_CYCLE, never a loop. */
    pic_u32 forward_depth;
    pic_u32 forward_visited_count;
    PIC_HASH forward_visited[PIC_MAX_FORWARD_VISITED];
} PIC_CONTEXT;

PIC_PEB *PIC_MS_ABI pic_current_peb(void);
void PIC_MS_ABI pic_hash_ascii_upper(const pic_u8 *data, pic_u32 length,
                                     PIC_HASH *out);
void PIC_MS_ABI pic_hash_utf16_upper(const pic_u16 *data, pic_u32 code_units,
                                     PIC_HASH *out);
PIC_RESOLVE_STATUS PIC_MS_ABI pic_find_module(PIC_CONTEXT *ctx,
                                               const PIC_HASH *module_hash,
                                               void **module_base);
PIC_RESOLVE_STATUS PIC_MS_ABI pic_resolve_export(PIC_CONTEXT *ctx,
                                                  void *module_base,
                                                  const PIC_HASH *export_hash,
                                                  void **address);
PIC_RESOLVE_STATUS PIC_MS_ABI pic_resolve_ordinal(PIC_CONTEXT *ctx,
                                                   void *module_base,
                                                   pic_u16 ordinal,
                                                   void **address);
PIC_RESOLVE_STATUS PIC_MS_ABI pic_resolve_forwarder(PIC_CONTEXT *ctx,
                                                     const char *forwarder,
                                                     pic_u32 forwarder_length,
                                                     pic_u32 depth,
                                                     void **address);
PIC_RESOLVE_STATUS PIC_MS_ABI pic_resolve_apiset_contract(PIC_CONTEXT *ctx,
                                                           const pic_u16 *contract,
                                                           pic_u32 contract_code_units,
                                                           void **module_base);

#endif /* MARGARET_PIC_RESOLVE_H */
