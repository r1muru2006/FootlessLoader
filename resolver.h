#ifndef FOOTLESS_RESOLVER_H
#define FOOTLESS_RESOLVER_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdint.h>

#include "hash.h"

typedef enum FOOTLESS_RESOLVE_STATUS {
    FOOTLESS_RESOLVE_OK = 0,
    FOOTLESS_RESOLVE_INVALID_ARGUMENT,
    FOOTLESS_RESOLVE_INVALID_PE,
    FOOTLESS_RESOLVE_NO_EXPORTS,
    FOOTLESS_RESOLVE_NOT_FOUND,
    FOOTLESS_RESOLVE_FORWARDER,
    FOOTLESS_RESOLVE_INVALID_EXPORT
} FOOTLESS_RESOLVE_STATUS;

typedef struct FOOTLESS_RESOLVE_INFO {
    FOOTLESS_RESOLVE_STATUS status;
    uint32_t target_hash;
    uint32_t matched_hash;
    DWORD name_index;
    WORD ordinal;
    DWORD function_rva;
    BOOL forwarded;
    char matched_name[128];
} FOOTLESS_RESOLVE_INFO;

BOOL footless_get_or_load_module(const wchar_t *module_name, HMODULE *module_out);

BOOL footless_resolve_export_by_hash(HMODULE module,
                                     const char *module_name,
                                     uint32_t target_hash,
                                     FOOTLESS_HASH_VARIANT variant,
                                     uint32_t seed,
                                     void **address_out,
                                     FOOTLESS_RESOLVE_INFO *info_out);

const char *footless_resolve_status_name(FOOTLESS_RESOLVE_STATUS status);

#endif
