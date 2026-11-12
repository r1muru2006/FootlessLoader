#ifndef FOOTLESS_RESOLVER_H
#define FOOTLESS_RESOLVER_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
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

/*
 * Full x64 loader-data entry.  The public winternl.h only exposes the
 * InMemoryOrder list; we walk InLoadOrder and need BaseDllName, so the
 * layout is spelled out explicitly and documented in docs/DESIGN.md.
 */
typedef struct FOOTLESS_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} FOOTLESS_LDR_ENTRY, *PFOOTLESS_LDR_ENTRY;

/* Walk the PEB InLoadOrder list; no GetModuleHandle/LoadLibrary needed. */
HMODULE footless_module_by_hash(uint32_t name_hash, uint32_t seed);

BOOL footless_resolve_export_by_hash(HMODULE module,
                                     const char *module_name,
                                     uint32_t target_hash,
                                     FOOTLESS_HASH_VARIANT variant,
                                     uint32_t seed,
                                     void **address_out,
                                     FOOTLESS_RESOLVE_INFO *info_out);

/* Compute module+API hashes, find the loaded module through the PEB, and
 * resolve the export.  Returns FALSE and fills info->status on failure. */
BOOL footless_resolve_api_by_hash(const char *module_name_ascii,
                                  const char *api_name_ascii,
                                  FOOTLESS_HASH_VARIANT variant,
                                  uint32_t seed,
                                  void **address_out,
                                  FOOTLESS_RESOLVE_INFO *info_out);

const char *footless_resolve_status_name(FOOTLESS_RESOLVE_STATUS status);

#endif
