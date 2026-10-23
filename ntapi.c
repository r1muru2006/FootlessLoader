#include "ntapi.h"

#include <string.h>

typedef struct FOOTLESS_API_REQUEST {
    const char *name;
    void **slot;
} FOOTLESS_API_REQUEST;

BOOL footless_init_ntapi_table(FOOTLESS_HASH_VARIANT variant,
                               uint32_t seed,
                               FOOTLESS_NTAPI_TABLE *table_out) {
    static const char module_name[] = "ntdll.dll";
    static const wchar_t module_name_wide[] = L"ntdll.dll";
    static const char rtl_get_version_name[] = "RtlGetVersion";
    static const char nt_close_name[] = "NtClose";
    static const char nt_query_information_process_name[] = "NtQueryInformationProcess";
    HMODULE module = NULL;
    FOOTLESS_API_REQUEST requests[3];
    size_t index;

    if (table_out == NULL) {
        return FALSE;
    }
    ZeroMemory(table_out, sizeof(*table_out));
    if (!footless_get_or_load_module(module_name_wide, &module)) {
        return FALSE;
    }
    requests[0].name = rtl_get_version_name;
    requests[0].slot = (void **)&table_out->rtl_get_version;
    requests[1].name = nt_close_name;
    requests[1].slot = (void **)&table_out->nt_close;
    requests[2].name = nt_query_information_process_name;
    requests[2].slot = (void **)&table_out->nt_query_information_process;

    for (index = 0U; index < sizeof(requests) / sizeof(requests[0]); ++index) {
        void *address = NULL;
        uint32_t target_hash = footless_hash_for_variant(
            variant, module_name, requests[index].name, seed);
        if (!footless_resolve_export_by_hash(module, module_name, target_hash,
                                             variant, seed, &address, NULL)) {
            ZeroMemory(table_out, sizeof(*table_out));
            return FALSE;
        }
        *requests[index].slot = address;
    }
    return TRUE;
}
