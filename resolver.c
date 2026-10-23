#include "resolver.h"

#include <string.h>

static void clear_info(FOOTLESS_RESOLVE_INFO *info, uint32_t target_hash) {
    if (info == NULL) {
        return;
    }
    ZeroMemory(info, sizeof(*info));
    info->status = FOOTLESS_RESOLVE_INVALID_ARGUMENT;
    info->target_hash = target_hash;
}

static BOOL rva_span(BYTE *base, DWORD image_size, DWORD rva,
                     SIZE_T length, BYTE **address_out) {
    uint64_t end;

    if (base == NULL || address_out == NULL) {
        return FALSE;
    }
    end = (uint64_t)rva + (uint64_t)length;
    if (end > (uint64_t)image_size) {
        return FALSE;
    }
    *address_out = base + rva;
    return TRUE;
}

static BOOL bounded_export_string(BYTE *base, DWORD image_size, DWORD rva,
                                  const char **string_out, size_t *length_out) {
    const char *text;
    size_t available;
    size_t index;

    if (string_out == NULL || length_out == NULL || rva >= image_size) {
        return FALSE;
    }
    text = (const char *)(base + rva);
    available = (size_t)image_size - (size_t)rva;
    for (index = 0U; index < available; ++index) {
        if (text[index] == '\0') {
            *string_out = text;
            *length_out = index;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL image_export_layout(HMODULE module,
                                BYTE **base_out,
                                DWORD *image_size_out,
                                PIMAGE_EXPORT_DIRECTORY *exports_out,
                                DWORD *export_rva_out,
                                DWORD *export_size_out) {
    BYTE *base;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    IMAGE_DATA_DIRECTORY directory;

    if (module == NULL || base_out == NULL || image_size_out == NULL ||
        exports_out == NULL || export_rva_out == NULL || export_size_out == NULL) {
        return FALSE;
    }
    base = (BYTE *)module;
    dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        dos->e_lfanew > 0x01000000L) {
        return FALSE;
    }
    nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->OptionalHeader.SizeOfImage == 0U) {
        return FALSE;
    }
    directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (directory.VirtualAddress == 0U || directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY) ||
        (uint64_t)directory.VirtualAddress + directory.Size > nt->OptionalHeader.SizeOfImage) {
        return FALSE;
    }
    if (!rva_span(base, nt->OptionalHeader.SizeOfImage, directory.VirtualAddress,
                  sizeof(IMAGE_EXPORT_DIRECTORY), (BYTE **)exports_out)) {
        return FALSE;
    }
    *base_out = base;
    *image_size_out = nt->OptionalHeader.SizeOfImage;
    *export_rva_out = directory.VirtualAddress;
    *export_size_out = directory.Size;
    return TRUE;
}

BOOL footless_get_or_load_module(const wchar_t *module_name, HMODULE *module_out) {
    HMODULE module;

    if (module_name == NULL || module_out == NULL) {
        return FALSE;
    }
    module = GetModuleHandleW(module_name);
    if (module == NULL) {
        module = LoadLibraryW(module_name);
    }
    if (module == NULL) {
        *module_out = NULL;
        return FALSE;
    }
    *module_out = module;
    return TRUE;
}

BOOL footless_resolve_export_by_hash(HMODULE module,
                                     const char *module_name,
                                     uint32_t target_hash,
                                     FOOTLESS_HASH_VARIANT variant,
                                     uint32_t seed,
                                     void **address_out,
                                     FOOTLESS_RESOLVE_INFO *info_out) {
    BYTE *base;
    DWORD image_size;
    PIMAGE_EXPORT_DIRECTORY exports;
    DWORD export_rva;
    DWORD export_size;
    BYTE *names_bytes;
    BYTE *ordinals_bytes;
    BYTE *functions_bytes;
    DWORD *names;
    WORD *ordinals;
    DWORD *functions;
    DWORD index;

    clear_info(info_out, target_hash);
    if (address_out != NULL) {
        *address_out = NULL;
    }
    if (module == NULL || address_out == NULL ||
        (variant == FOOTLESS_HASH_MODULE_API && module_name == NULL)) {
        return FALSE;
    }
    if (!image_export_layout(module, &base, &image_size, &exports,
                             &export_rva, &export_size)) {
        if (info_out != NULL) {
            info_out->status = FOOTLESS_RESOLVE_INVALID_PE;
        }
        return FALSE;
    }
    if (exports->NumberOfNames == 0U || exports->NumberOfFunctions == 0U) {
        if (info_out != NULL) {
            info_out->status = FOOTLESS_RESOLVE_NO_EXPORTS;
        }
        return FALSE;
    }
    if (!rva_span(base, image_size, exports->AddressOfNames,
                  (SIZE_T)exports->NumberOfNames * sizeof(DWORD), &names_bytes) ||
        !rva_span(base, image_size, exports->AddressOfNameOrdinals,
                  (SIZE_T)exports->NumberOfNames * sizeof(WORD), &ordinals_bytes) ||
        !rva_span(base, image_size, exports->AddressOfFunctions,
                  (SIZE_T)exports->NumberOfFunctions * sizeof(DWORD), &functions_bytes)) {
        if (info_out != NULL) {
            info_out->status = FOOTLESS_RESOLVE_INVALID_EXPORT;
        }
        return FALSE;
    }
    names = (DWORD *)names_bytes;
    ordinals = (WORD *)ordinals_bytes;
    functions = (DWORD *)functions_bytes;

    for (index = 0U; index < exports->NumberOfNames; ++index) {
        const char *export_name;
        size_t export_name_length;
        uint32_t hash;
        WORD ordinal;
        DWORD function_rva;
        BYTE *function_address;

        if (!bounded_export_string(base, image_size, names[index],
                                   &export_name, &export_name_length)) {
            continue;
        }
        if (variant == FOOTLESS_HASH_MODULE_API) {
            hash = footless_hash_module_api(module_name, strlen(module_name),
                                            export_name, export_name_length, seed);
        } else if (variant == FOOTLESS_HASH_BASELINE) {
            hash = footless_hash_baseline(export_name, export_name_length, seed);
        } else if (variant == FOOTLESS_HASH_SEEDED) {
            hash = footless_hash_seeded(export_name, export_name_length, seed);
        } else {
            continue;
        }
        if (hash != target_hash) {
            continue;
        }
        ordinal = ordinals[index];
        if ((DWORD)ordinal >= exports->NumberOfFunctions) {
            if (info_out != NULL) {
                info_out->status = FOOTLESS_RESOLVE_INVALID_EXPORT;
            }
            return FALSE;
        }
        function_rva = functions[ordinal];
        if ((uint64_t)function_rva >= export_rva &&
            (uint64_t)function_rva < (uint64_t)export_rva + export_size) {
            if (info_out != NULL) {
                info_out->status = FOOTLESS_RESOLVE_FORWARDER;
                info_out->forwarded = TRUE;
                info_out->name_index = index;
                info_out->ordinal = ordinal;
                info_out->matched_hash = hash;
                strncpy(info_out->matched_name, export_name,
                        sizeof(info_out->matched_name) - 1U);
                info_out->matched_name[sizeof(info_out->matched_name) - 1U] = '\0';
            }
            return FALSE;
        }
        if (!rva_span(base, image_size, function_rva, 1U, &function_address)) {
            if (info_out != NULL) {
                info_out->status = FOOTLESS_RESOLVE_INVALID_EXPORT;
            }
            return FALSE;
        }
        if (info_out != NULL) {
            info_out->status = FOOTLESS_RESOLVE_OK;
            info_out->matched_hash = hash;
            info_out->name_index = index;
            info_out->ordinal = ordinal;
            info_out->function_rva = function_rva;
            strncpy(info_out->matched_name, export_name,
                    sizeof(info_out->matched_name) - 1U);
            info_out->matched_name[sizeof(info_out->matched_name) - 1U] = '\0';
        }
        *address_out = (void *)function_address;
        return TRUE;
    }
    if (info_out != NULL) {
        info_out->status = FOOTLESS_RESOLVE_NOT_FOUND;
    }
    return FALSE;
}

const char *footless_resolve_status_name(FOOTLESS_RESOLVE_STATUS status) {
    switch (status) {
        case FOOTLESS_RESOLVE_OK:
            return "ok";
        case FOOTLESS_RESOLVE_INVALID_ARGUMENT:
            return "invalid_argument";
        case FOOTLESS_RESOLVE_INVALID_PE:
            return "invalid_pe";
        case FOOTLESS_RESOLVE_NO_EXPORTS:
            return "no_exports";
        case FOOTLESS_RESOLVE_NOT_FOUND:
            return "not_found";
        case FOOTLESS_RESOLVE_FORWARDER:
            return "forwarded_export_not_supported";
        case FOOTLESS_RESOLVE_INVALID_EXPORT:
            return "invalid_export";
        default:
            return "unknown";
    }
}
