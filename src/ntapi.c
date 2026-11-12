#include "ntapi.h"

#include <string.h>
#include <wchar.h>

#ifndef FOOTLESS_API_HASHES_HEADER
#define FOOTLESS_API_HASHES_HEADER "api_hashes.h"
#endif
#include FOOTLESS_API_HASHES_HEADER

/* Minimal x64 SYSTEM_PROCESS_INFORMATION (documented layout, Win7+). */
typedef struct FOOTLESS_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} FOOTLESS_SYSTEM_PROCESS_INFORMATION;

typedef struct FOOTLESS_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    ULONG Reserved;
    PVOID StartAddress;
    FOOTLESS_CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
    ULONG Reserved2;
} FOOTLESS_SYSTEM_THREAD_INFORMATION;

typedef struct FOOTLESS_API_REQUEST {
    const char *module;
    const char *name;
    void **slot;
} FOOTLESS_API_REQUEST;

#define FOOTLESS_STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

static const wchar_t *footless_basename(const wchar_t *path) {
    const wchar_t *slash = wcsrchr(path, L'\\');
    const wchar_t *fwd = wcsrchr(path, L'/');
    const wchar_t *best = path;
    if (slash != NULL && slash + 1 > best) {
        best = slash + 1;
    }
    if (fwd != NULL && fwd + 1 > best) {
        best = fwd + 1;
    }
    return best;
}

static BOOL footless_name_equals(const wchar_t *left, const wchar_t *right) {
    return _wcsicmp(footless_basename(left), footless_basename(right)) == 0;
}

static void *footless_query_system_buffer(FOOTLESS_API_TABLE *table,
                                          ULONG *length_out) {
    SIZE_T size = 256U * 1024U;
    void *buffer = NULL;
    NTSTATUS status;

    if (table == NULL || table->nt_query_system_information == NULL) {
        return NULL;
    }
    while (size <= 64U * 1024U * 1024U) {
        ULONG needed = 0U;
        buffer = VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT,
                              PAGE_READWRITE);
        if (buffer == NULL) {
            return NULL;
        }
        status = table->nt_query_system_information(5U, buffer, (ULONG)size,
                                                    &needed);
        if (status >= 0) {
            if (length_out != NULL) {
                *length_out = needed;
            }
            return buffer;
        }
        VirtualFree(buffer, 0U, MEM_RELEASE);
        buffer = NULL;
        if (status != FOOTLESS_STATUS_INFO_LENGTH_MISMATCH) {
            return NULL;
        }
        size = needed > size ? (SIZE_T)needed + 4096U : size * 2U;
    }
    return NULL;
}

DWORD footless_find_process_by_name(const wchar_t *image_name,
                                    FOOTLESS_API_TABLE *table) {
    void *buffer;
    BYTE *cursor;
    unsigned int guard = 0U;

    if (image_name == NULL || table == NULL) {
        return 0U;
    }
    buffer = footless_query_system_buffer(table, NULL);
    if (buffer == NULL) {
        return 0U;
    }
    cursor = (BYTE *)buffer;
    while (cursor != NULL && guard < 100000U) {
        FOOTLESS_SYSTEM_PROCESS_INFORMATION *entry =
            (FOOTLESS_SYSTEM_PROCESS_INFORMATION *)cursor;
        if (entry->ImageName.Buffer != NULL &&
            entry->ImageName.Length >= sizeof(WCHAR) &&
            footless_name_equals(entry->ImageName.Buffer, image_name)) {
            DWORD pid = (DWORD)(ULONG_PTR)entry->UniqueProcessId;
            VirtualFree(buffer, 0U, MEM_RELEASE);
            return pid;
        }
        if (entry->NextEntryOffset == 0U) {
            break;
        }
        cursor += entry->NextEntryOffset;
        ++guard;
    }
    VirtualFree(buffer, 0U, MEM_RELEASE);
    return 0U;
}

DWORD footless_find_first_thread(DWORD process_id, FOOTLESS_API_TABLE *table) {
    void *buffer;
    BYTE *cursor;
    unsigned int guard = 0U;
    DWORD tid = 0U;

    if (process_id == 0U || table == NULL) {
        return 0U;
    }
    buffer = footless_query_system_buffer(table, NULL);
    if (buffer == NULL) {
        return 0U;
    }
    cursor = (BYTE *)buffer;
    while (cursor != NULL && guard < 100000U) {
        FOOTLESS_SYSTEM_PROCESS_INFORMATION *entry =
            (FOOTLESS_SYSTEM_PROCESS_INFORMATION *)cursor;
        if ((DWORD)(ULONG_PTR)entry->UniqueProcessId == process_id) {
            BYTE *thread_cursor = cursor + sizeof(*entry);
            ULONG index;
            for (index = 0U; index < entry->NumberOfThreads; ++index) {
                FOOTLESS_SYSTEM_THREAD_INFORMATION *thread =
                    (FOOTLESS_SYSTEM_THREAD_INFORMATION *)thread_cursor;
                if (thread->ClientId.UniqueThread != NULL) {
                    tid = (DWORD)(ULONG_PTR)thread->ClientId.UniqueThread;
                    break;
                }
                thread_cursor += sizeof(*thread);
            }
            break;
        }
        if (entry->NextEntryOffset == 0U) {
            break;
        }
        cursor += entry->NextEntryOffset;
        ++guard;
    }
    VirtualFree(buffer, 0U, MEM_RELEASE);
    return tid;
}

BOOL footless_init_api_table(FOOTLESS_HASH_VARIANT variant,
                             uint32_t seed,
                             FOOTLESS_API_TABLE *table_out) {
    static const char *const module_names[2] = {"ntdll.dll", "kernel32.dll"};
    FOOTLESS_API_REQUEST requests[FOOTLESS_GENERATED_API_COUNT];
    HMODULE modules[2] = {NULL, NULL};
    size_t index;
    (void)seed; /* hashes are compile-time constants for the build seed */

    if (table_out == NULL || (int)variant < 0 ||
        variant >= FOOTLESS_HASH_VARIANT_COUNT) {
        return FALSE;
    }
    ZeroMemory(table_out, sizeof(*table_out));
#define FOOTLESS_REQ(field, module_index, api_index)                        \
    do {                                                                    \
        requests[api_index].module = module_names[(module_index)];          \
        requests[api_index].name = NULL;                                    \
        requests[api_index].slot =                                          \
            (void **)(void *)&table_out->field;                             \
    } while (0)

    FOOTLESS_REQ(rtl_get_version, 0, 0);
    FOOTLESS_REQ(nt_close, 0, 1);
    FOOTLESS_REQ(nt_open_process, 0, 2);
    FOOTLESS_REQ(nt_allocate_virtual_memory, 0, 3);
    FOOTLESS_REQ(nt_write_virtual_memory, 0, 4);
    FOOTLESS_REQ(nt_read_virtual_memory, 0, 5);
    FOOTLESS_REQ(nt_protect_virtual_memory, 0, 6);
    FOOTLESS_REQ(nt_free_virtual_memory, 0, 7);
    FOOTLESS_REQ(nt_create_thread_ex, 0, 8);
    FOOTLESS_REQ(nt_open_thread, 0, 9);
    FOOTLESS_REQ(nt_queue_apc_thread, 0, 10);
    FOOTLESS_REQ(nt_query_system_information, 0, 11);
    FOOTLESS_REQ(nt_create_section, 0, 12);
    FOOTLESS_REQ(nt_map_view_of_section, 0, 13);
    FOOTLESS_REQ(nt_unmap_view_of_section, 0, 14);
    FOOTLESS_REQ(nt_wait_for_single_object, 0, 15);
    FOOTLESS_REQ(nt_query_information_process, 0, 16);
    FOOTLESS_REQ(load_library_w, 1, 17);
    FOOTLESS_REQ(create_remote_thread, 1, 18);
    FOOTLESS_REQ(query_full_process_image_name, 1, 19);
    FOOTLESS_REQ(is_wow64_process, 1, 20);
    FOOTLESS_REQ(get_exit_code_thread, 1, 21);
    FOOTLESS_REQ(close_handle, 1, 22);
    FOOTLESS_REQ(wait_for_single_object, 1, 23);
    FOOTLESS_REQ(flush_instruction_cache, 1, 24);
    FOOTLESS_REQ(sleep_fn, 1, 25);
    FOOTLESS_REQ(get_thread_id, 1, 26);
#undef FOOTLESS_REQ

    for (index = 0U; index < FOOTLESS_GENERATED_API_COUNT; ++index) {
        void *address = NULL;
        uint8_t module_index = footless_generated_module_index[index];
        uint32_t target_hash;
        if (module_index >= 2U) {
            ZeroMemory(table_out, sizeof(*table_out));
            return FALSE;
        }
        if (modules[module_index] == NULL) {
            modules[module_index] = footless_module_by_hash(
                footless_generated_module_hash[module_index],
                FOOTLESS_GENERATED_SEED);
            if (modules[module_index] == NULL) {
                ZeroMemory(table_out, sizeof(*table_out));
                return FALSE;
            }
        }
        target_hash = footless_generated_api_hash[index][(int)variant];
        if (!footless_resolve_export_by_hash(
                modules[module_index], module_names[module_index],
                target_hash, variant, FOOTLESS_GENERATED_SEED, &address,
                NULL) ||
            address == NULL) {
            ZeroMemory(table_out, sizeof(*table_out));
            return FALSE;
        }
        *requests[index].slot = address;
    }
    return TRUE;
}

unsigned int footless_api_table_size(void) {
    return (unsigned int)(sizeof(FOOTLESS_API_TABLE) / sizeof(void *));
}
