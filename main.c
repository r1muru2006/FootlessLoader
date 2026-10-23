#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdio.h>
#include <string.h>

#include "hash.h"
#include "ntapi.h"
#include "resolver.h"

static const char module_name[] = "ntdll.dll";
static const wchar_t module_name_wide[] = L"ntdll.dll";
static const char *const api_names[] = {
    "RtlGetVersion",
    "NtClose",
    "NtQueryInformationProcess"
};

static int run_variant(FOOTLESS_HASH_VARIANT variant, HMODULE module) {
    const uint32_t seed = UINT32_C(0x13579bdf) +
                          (uint32_t)variant * UINT32_C(0x11111111);
    size_t index;
    int failures = 0;

    printf("[variant] %s (seed=0x%08lx)\n",
           footless_hash_variant_name(variant), (unsigned long)seed);
    for (index = 0U; index < sizeof(api_names) / sizeof(api_names[0]); ++index) {
        uint32_t target_hash = footless_hash_for_variant(
            variant, module_name, api_names[index], seed);
        void *address = NULL;
        FOOTLESS_RESOLVE_INFO info;
        BOOL ok = footless_resolve_export_by_hash(
            module, module_name, target_hash, variant, seed, &address, &info);

        printf("  %-28s hash=0x%08lx status=%s address=%p\n",
               api_names[index], (unsigned long)target_hash,
               footless_resolve_status_name(info.status), address);
        if (!ok || address == NULL || strcmp(info.matched_name, api_names[index]) != 0) {
            ++failures;
        }
    }
    return failures;
}

static int test_missing_hash(FOOTLESS_HASH_VARIANT variant, HMODULE module) {
    const uint32_t seed = UINT32_C(0x13579bdf) +
                          (uint32_t)variant * UINT32_C(0x11111111);
    const uint32_t missing_hash = UINT32_C(0xdeadbeef);
    void *address = NULL;
    FOOTLESS_RESOLVE_INFO info;
    BOOL ok = footless_resolve_export_by_hash(
        module, module_name, missing_hash, variant, seed, &address, &info);

    printf("[negative] %-22s status=%s address=%p\n",
           footless_hash_variant_name(variant),
           footless_resolve_status_name(info.status), address);
    return ok || address != NULL || info.status != FOOTLESS_RESOLVE_NOT_FOUND;
}

int main(void) {
    HMODULE module = NULL;
    FOOTLESS_NTAPI_TABLE table;
    OSVERSIONINFOW version_info;
    LONG version_status;
    int failures = 0;
    FOOTLESS_HASH_VARIANT variant;

    if (!footless_get_or_load_module(module_name_wide, &module)) {
        fprintf(stderr, "[FAIL] ntdll.dll is not loaded\n");
        return 1;
    }
    printf("[+] Resolver lab; module=%p (%s)\n", (void *)module, module_name);

    for (variant = FOOTLESS_HASH_BASELINE;
         variant <= FOOTLESS_HASH_MODULE_API;
         variant = (FOOTLESS_HASH_VARIANT)((int)variant + 1)) {
        failures += run_variant(variant, module);
        failures += test_missing_hash(variant, module);
    }

    if (!footless_init_ntapi_table(FOOTLESS_HASH_BASELINE, UINT32_C(0x13579bdf), &table)) {
        fprintf(stderr, "[FAIL] API table initialization\n");
        ++failures;
    } else {
        ZeroMemory(&version_info, sizeof(version_info));
        version_info.dwOSVersionInfoSize = sizeof(version_info);
        version_status = table.rtl_get_version(&version_info);
        printf("[call] RtlGetVersion status=%ld version=%lu.%lu build=%lu\n",
               version_status, version_info.dwMajorVersion,
               version_info.dwMinorVersion, version_info.dwBuildNumber);
        if (version_status < 0) {
            ++failures;
        }
    }

    if (failures != 0) {
        fprintf(stderr, "[FAIL] resolver checks failed: %d\n", failures);
        return 1;
    }
    printf("[PASS] three resolver variants and negative lookup passed\n");
    return 0;
}
