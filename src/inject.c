#include "inject.h"

#include "log.h"

#include <stdio.h>
#include <string.h>
#include <wchar.h>

#ifdef FOOTLESS_QUIET
#define FOOTLESS_API_LABEL(name) "api"
#else
#define FOOTLESS_API_LABEL(name) name
#endif

#define FOOTLESS_SECTION_SIZE ((SIZE_T)0x1000U)

static const wchar_t *path_basename(const wchar_t *path) {
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

BOOL footless_target_name_allowed(const wchar_t *image_path) {
    const wchar_t *name = path_basename(image_path);
    return _wcsicmp(name, L"footless_target.exe") == 0 ||
           _wcsicmp(name, L"notepad.exe") == 0;
}

BOOL footless_marker_name_allowed(const wchar_t *dll_path) {
    return _wcsicmp(path_basename(dll_path), L"footless_marker.dll") == 0;
}

const char *footless_method_name(FOOTLESS_INJECT_METHOD method) {
    switch (method) {
        case FOOTLESS_METHOD_CRT:
            return "crt";
        case FOOTLESS_METHOD_NT:
            return "nt";
        case FOOTLESS_METHOD_STUB:
            return "stub";
        case FOOTLESS_METHOD_APC:
            return "apc";
        case FOOTLESS_METHOD_SECTION:
            return "section";
        default:
            return "unknown";
    }
}

int footless_method_from_name(const char *name,
                              FOOTLESS_INJECT_METHOD *method_out) {
    if (name == NULL || method_out == NULL) {
        return 0;
    }
    if (strcmp(name, "crt") == 0) {
        *method_out = FOOTLESS_METHOD_CRT;
        return 1;
    }
    if (strcmp(name, "nt") == 0) {
        *method_out = FOOTLESS_METHOD_NT;
        return 1;
    }
    if (strcmp(name, "stub") == 0) {
        *method_out = FOOTLESS_METHOD_STUB;
        return 1;
    }
    if (strcmp(name, "apc") == 0) {
        *method_out = FOOTLESS_METHOD_APC;
        return 1;
    }
    if (strcmp(name, "section") == 0) {
        *method_out = FOOTLESS_METHOD_SECTION;
        return 1;
    }
    return 0;
}

static void json_path(const wchar_t *path, char *out, size_t cap) {
    footless_json_escape_wide(path, out, cap);
}

static void log_error(const char *stage, LONG status, DWORD error) {
    footless_log_event("error",
                       "\"stage\":\"%s\",\"ntstatus\":\"0x%08lx\","
                       "\"win32_error\":%lu",
                       stage, (unsigned long)status, (unsigned long)error);
}

static BOOL remote_alloc(FOOTLESS_API_TABLE *table, HANDLE process,
                         SIZE_T size, ULONG protection, PVOID *address_out,
                         LONG *status_out) {
    PVOID base = NULL;
    SIZE_T region = size;
    LONG status = table->nt_allocate_virtual_memory(
        process, &base, 0U, &region, MEM_COMMIT | MEM_RESERVE, protection);
    if (status_out != NULL) {
        *status_out = status;
    }
    if (status < 0 || base == NULL) {
        return FALSE;
    }
    *address_out = base;
    return TRUE;
}

static BOOL remote_free(FOOTLESS_API_TABLE *table, HANDLE process,
                        PVOID address) {
    PVOID base = address;
    SIZE_T size = 0U;
    LONG status = table->nt_free_virtual_memory(process, &base, &size,
                                                MEM_RELEASE);
    footless_log_event("memory_free",
                       "\"operation\":\"free_memory\",\"base_address\":\"0x%llx\","
                       "\"ntstatus\":\"0x%08lx\"",
                       (unsigned long long)(ULONG_PTR)address,
                       (unsigned long)status);
    return status >= 0;
}

static BOOL remote_write(FOOTLESS_API_TABLE *table, HANDLE process,
                         PVOID address, const void *data, SIZE_T size) {
    SIZE_T written = 0U;
    LONG status = table->nt_write_virtual_memory(process, address, data, size,
                                                 &written);
    footless_log_event("memory_write",
                       "\"operation\":\"write_memory\",\"base_address\":\"0x%llx\","
                       "\"size\":%llu,\"bytes_written\":%llu,"
                       "\"ntstatus\":\"0x%08lx\"",
                       (unsigned long long)(ULONG_PTR)address,
                       (unsigned long long)size,
                       (unsigned long long)written, (unsigned long)status);
    return status >= 0 && written == size;
}

static BOOL remote_protect(FOOTLESS_API_TABLE *table, HANDLE process,
                           PVOID address, SIZE_T size, ULONG protection,
                           const char *label) {
    PVOID base = address;
    SIZE_T region = size;
    ULONG old = 0U;
    LONG status = table->nt_protect_virtual_memory(process, &base, &region,
                                                   protection, &old);
    footless_log_event("memory_protect",
                       "\"operation\":\"protect_memory\",\"base_address\":\"0x%llx\","
                       "\"size\":%llu,\"old_protection\":\"0x%lx\","
                       "\"memory_protection\":\"%s\",\"ntstatus\":\"0x%08lx\"",
                       (unsigned long long)(ULONG_PTR)address,
                       (unsigned long long)size, (unsigned long)old, label,
                       (unsigned long)status);
    return status >= 0;
}

static SIZE_T build_stub_full(unsigned char *stub, size_t capacity,
                              ULONGLONG function_address, ULONGLONG argument) {
    static const unsigned char prefix[] = {0x48, 0xb8};
    static const unsigned char mov_rcx[] = {0x48, 0xb9};
    static const unsigned char epilogue[] = {0x48, 0x83, 0xec, 0x28,
                                             0xff, 0xd0, 0x48, 0x83,
                                             0xc4, 0x28, 0xc3};
    size_t used = 0U;
    size_t index;

    if (capacity < 24U) {
        return 0U;
    }
    memcpy(stub + used, prefix, sizeof(prefix));
    used += sizeof(prefix);
    for (index = 0U; index < 8U; ++index) {
        stub[used + index] =
            (unsigned char)(function_address >> (8U * index));
    }
    used += 8U;
    memcpy(stub + used, mov_rcx, sizeof(mov_rcx));
    used += sizeof(mov_rcx);
    for (index = 0U; index < 8U; ++index) {
        stub[used + index] = (unsigned char)(argument >> (8U * index));
    }
    used += 8U;
    memcpy(stub + used, epilogue, sizeof(epilogue));
    used += sizeof(epilogue);
    return used;
}

static BOOL wait_thread(FOOTLESS_API_TABLE *table, HANDLE thread,
                        DWORD timeout_ms, DWORD *exit_code_out) {
    DWORD wait = table->wait_for_single_object(thread, timeout_ms);
    if (wait != WAIT_OBJECT_0) {
        footless_log_event("thread_wait",
                           "\"wait_result\":%lu,\"timeout_ms\":%lu",
                           (unsigned long)wait, (unsigned long)timeout_ms);
        return FALSE;
    }
    if (exit_code_out != NULL &&
        !table->get_exit_code_thread(thread, exit_code_out)) {
        footless_log_event("thread_exit",
                           "\"win32_error\":%lu",
                           (unsigned long)GetLastError());
        return FALSE;
    }
    footless_log_event("thread_exit", "\"exit_code\":%lu",
                       (unsigned long)(exit_code_out != NULL ? *exit_code_out
                                                             : 0UL));
    return TRUE;
}

static BOOL create_thread(FOOTLESS_API_TABLE *table, HANDLE process,
                          PVOID start, PVOID argument, BOOL use_nt,
                          HANDLE *thread_out, DWORD *tid_out,
                          LONG *status_out) {
    HANDLE thread = NULL;
    DWORD tid = 0U;
    LONG status = 0;

    if (use_nt) {
        status = table->nt_create_thread_ex(
            &thread, THREAD_QUERY_INFORMATION | SYNCHRONIZE, NULL, process,
            start, argument, 0U, 0U, 0U, 0U, NULL);
        if (status >= 0 && thread != NULL) {
            tid = table->get_thread_id(thread);
        }
    } else {
        thread = table->create_remote_thread(
            process, NULL, 0U, (LPTHREAD_START_ROUTINE)start, argument, 0U,
            &tid);
        if (thread == NULL) {
            status = (LONG)GetLastError();
        }
    }
    if (status_out != NULL) {
        *status_out = status;
    }
    if (thread == NULL || status < 0) {
        if (thread != NULL) {
            table->close_handle(thread);
        }
        return FALSE;
    }
    if (tid_out != NULL) {
        *tid_out = tid;
    }
    if (thread_out != NULL) {
        *thread_out = thread;
    }
    return TRUE;
}

static int common_dll_flow(FOOTLESS_API_TABLE *table, HANDLE process,
                           const FOOTLESS_INJECT_OPTIONS *options,
                           FOOTLESS_INJECT_RESULT *result) {
    SIZE_T path_bytes =
        (wcslen(options->dll_path) + 1U) * sizeof(WCHAR);
    PVOID remote_path = NULL;
    PVOID remote_stub = NULL;
    HANDLE thread = NULL;
    DWORD exit_code = 0U;
    LONG status = 0;
    BOOL stub_method = options->method == FOOTLESS_METHOD_STUB ||
                        options->method == FOOTLESS_METHOD_APC;
    BOOL ok = FALSE;
    char dll_escaped[MAX_PATH * 3];

    json_path(options->dll_path, dll_escaped, sizeof(dll_escaped));
    if (!remote_alloc(table, process, path_bytes, PAGE_READWRITE,
                      &remote_path, &status)) {
        log_error("allocate_path", status, GetLastError());
        return 10;
    }
    footless_log_event("memory_allocate",
                       "\"operation\":\"allocate_memory\",\"base_address\":\"0x%llx\","
                       "\"size\":%llu,\"memory_protection\":\"RW\"",
                       (unsigned long long)(ULONG_PTR)remote_path,
                       (unsigned long long)path_bytes);
    if (!remote_write(table, process, remote_path, options->dll_path,
                      path_bytes)) {
        remote_free(table, process, remote_path);
        return 11;
    }
    if (stub_method) {
        unsigned char stub[32];
        SIZE_T stub_length = build_stub_full(
            stub, sizeof(stub),
            (ULONGLONG)(ULONG_PTR)table->load_library_w,
            (ULONGLONG)(ULONG_PTR)remote_path);
        if (stub_length == 0U) {
            remote_free(table, process, remote_path);
            return 12;
        }
        if (!remote_alloc(table, process, stub_length, PAGE_READWRITE,
                          &remote_stub, &status)) {
            log_error("allocate_stub", status, GetLastError());
            remote_free(table, process, remote_path);
            return 12;
        }
        footless_log_event("memory_allocate",
                           "\"operation\":\"allocate_memory\","
                           "\"base_address\":\"0x%llx\",\"size\":%llu,"
                           "\"memory_protection\":\"RW\"",
                           (unsigned long long)(ULONG_PTR)remote_stub,
                           (unsigned long long)stub_length);
        if (!remote_write(table, process, remote_stub, stub, stub_length) ||
            !remote_protect(table, process, remote_stub, stub_length,
                            PAGE_EXECUTE_READ, "RX")) {
            remote_free(table, process, remote_stub);
            remote_free(table, process, remote_path);
            return 13;
        }
    }
    if (options->method == FOOTLESS_METHOD_APC) {
        HANDLE target_thread = NULL;
        FOOTLESS_CLIENT_ID cid;
        FOOTLESS_OBJECT_ATTRIBUTES attributes;
        DWORD target_tid = options->target_tid;
        PVOID start = remote_stub != NULL ? remote_stub
                                          : (PVOID)(ULONG_PTR)table->load_library_w;
        PVOID argument = remote_stub != NULL ? NULL : remote_path;

        if (target_tid == 0U) {
            target_tid = footless_find_first_thread(options->target_pid, table);
        }
        if (target_tid == 0U) {
            log_error("apc_target_thread", 0, ERROR_NOT_FOUND);
            if (remote_stub != NULL) {
                remote_free(table, process, remote_stub);
            }
            remote_free(table, process, remote_path);
            return 14;
        }
        ZeroMemory(&attributes, sizeof(attributes));
        attributes.Length = sizeof(attributes);
        cid.UniqueProcess = (HANDLE)(ULONG_PTR)options->target_pid;
        cid.UniqueThread = (HANDLE)(ULONG_PTR)target_tid;
        status = table->nt_open_thread(
            &target_thread,
            THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | SYNCHRONIZE,
            &attributes, &cid);
        if (status < 0 || target_thread == NULL) {
            log_error("open_target_thread", status, GetLastError());
            if (remote_stub != NULL) {
                remote_free(table, process, remote_stub);
            }
            remote_free(table, process, remote_path);
            return 14;
        }
        status = table->nt_queue_apc_thread(target_thread, start, argument,
                                            NULL, NULL);
        footless_log_event("apc_queue",
                           "\"operation\":\"queue_apc\",\"api\":\"%s\","
                           "\"target_pid\":%lu,\"target_tid\":%lu,"
                           "\"callback_address\":\"0x%llx\","
                           "\"ntstatus\":\"0x%08lx\"",
                           FOOTLESS_API_LABEL("NtQueueApcThread"),
                           (unsigned long)options->target_pid,
                           (unsigned long)target_tid,
                           (unsigned long long)(ULONG_PTR)start,
                           (unsigned long)status);
        table->close_handle(target_thread);
        result->target_tid = target_tid;
        if (status < 0) {
            if (remote_stub != NULL) {
                remote_free(table, process, remote_stub);
            }
            remote_free(table, process, remote_path);
            return 15;
        }
        /* A queued APC is an attempt.  The marker log is the ground truth
           for dispatch; code is retained until the target exits. */
        table->sleep_fn(options->timeout_ms);
        footless_log_event("apc_observation",
                           "\"observation_limit_ms\":%lu,"
                           "\"cleanup\":\"deferred_until_target_exit\"",
                           (unsigned long)options->timeout_ms);
        result->ok = TRUE;
        return 0;
    }

    if (!create_thread(table, process,
                       stub_method ? remote_stub
                                   : (PVOID)(ULONG_PTR)table->load_library_w,
                       stub_method ? NULL : remote_path,
                       options->method == FOOTLESS_METHOD_NT, &thread,
                       &result->new_tid, &status)) {
        log_error("create_thread", status, GetLastError());
        if (remote_stub != NULL) {
            remote_free(table, process, remote_stub);
        }
        remote_free(table, process, remote_path);
        return 16;
    }
    footless_log_event("remote_thread",
                       "\"operation\":\"create_remote_thread\","
                       "\"api\":\"%s\",\"target_pid\":%lu,\"new_tid\":%lu,"
                       "\"start_address\":\"0x%llx\",\"argument\":\"0x%llx\"",
                       options->method == FOOTLESS_METHOD_NT
                           ? FOOTLESS_API_LABEL("NtCreateThreadEx")
                           : FOOTLESS_API_LABEL("CreateRemoteThread"),
                       (unsigned long)options->target_pid,
                       (unsigned long)result->new_tid,
                       (unsigned long long)(ULONG_PTR)(
                           stub_method ? remote_stub
                                       : (PVOID)(ULONG_PTR)table->load_library_w),
                       (unsigned long long)(ULONG_PTR)(
                           stub_method ? NULL : remote_path));
    ok = wait_thread(table, thread, options->timeout_ms, &exit_code);
    result->exit_code = (int)exit_code;
    table->close_handle(thread);
    if (ok) {
        if (remote_stub != NULL) {
            remote_free(table, process, remote_stub);
        }
        remote_free(table, process, remote_path);
    } else {
        /* A timed-out thread may still be executing the stub or reading the
           DLL path.  Retain the buffers until the target exits. */
        footless_log_event(
            "cleanup_deferred",
            "\"reason\":\"thread termination unconfirmed; remote buffers "
            "retained until target exit\"");
    }
    result->ok = ok;
    return ok ? 0 : 17;
}

static int section_flow(FOOTLESS_API_TABLE *table, HANDLE process,
                        const FOOTLESS_INJECT_OPTIONS *options,
                        FOOTLESS_INJECT_RESULT *result) {
    HANDLE section = NULL;
    PVOID remote_view = NULL;
    SIZE_T view_size = FOOTLESS_SECTION_SIZE;
    LARGE_INTEGER maximum_size;
    unsigned char payload[0x1000];
    SIZE_T path_offset = 0x200U;
    SIZE_T path_bytes;
    SIZE_T stub_length;
    LONG status;
    DWORD exit_code = 0U;
    HANDLE thread = NULL;
    BOOL ok = FALSE;

    if (wcslen(options->dll_path) * sizeof(WCHAR) + path_offset + 2U >
        sizeof(payload)) {
        return 20;
    }
    maximum_size.QuadPart = (LONGLONG)FOOTLESS_SECTION_SIZE;
    status = table->nt_create_section(&section, SECTION_ALL_ACCESS, NULL,
                                      &maximum_size, PAGE_EXECUTE_READWRITE,
                                      SEC_COMMIT, NULL);
    if (status < 0 || section == NULL) {
        log_error("create_section", status, GetLastError());
        return 20;
    }
    /* Map the section into the target as RW first so the stub and the DLL
       path can be written through the mapped view, then switch to RX.
       The memory stays section-backed (pagefile), not a private alloc. */
    status = table->nt_map_view_of_section(
        section, process, &remote_view, 0U, 0U, NULL, &view_size,
        FOOTLESS_VIEW_UNMAP, 0U, PAGE_READWRITE);
    if (status < 0 || remote_view == NULL) {
        log_error("map_remote_view", status, GetLastError());
        table->close_handle(section);
        return 22;
    }
    footless_log_event("memory_map",
                       "\"operation\":\"map_section\",\"base_address\":\"0x%llx\","
                       "\"size\":%llu,\"memory_protection\":\"RW\","
                       "\"memory_backing\":\"pagefile_section\"",
                       (unsigned long long)(ULONG_PTR)remote_view,
                       (unsigned long long)view_size);
    ZeroMemory(payload, sizeof(payload));
    path_bytes = (wcslen(options->dll_path) + 1U) * sizeof(WCHAR);
    memcpy(payload + path_offset, options->dll_path, path_bytes);
    stub_length = build_stub_full(
        payload, 32U, (ULONGLONG)(ULONG_PTR)table->load_library_w,
        (ULONGLONG)(ULONG_PTR)((BYTE *)remote_view + path_offset));
    if (stub_length == 0U) {
        table->nt_unmap_view_of_section(process, remote_view);
        table->close_handle(section);
        return 21;
    }
    if (!remote_write(table, process, remote_view, payload,
                      path_offset + path_bytes)) {
        table->nt_unmap_view_of_section(process, remote_view);
        table->close_handle(section);
        return 21;
    }
    if (!remote_protect(table, process, remote_view, view_size,
                        PAGE_EXECUTE_READ, "RX")) {
        table->nt_unmap_view_of_section(process, remote_view);
        table->close_handle(section);
        return 21;
    }
    if (!create_thread(table, process, remote_view, NULL, TRUE, &thread,
                       &result->new_tid, &status)) {
        log_error("create_thread_section", status, GetLastError());
        table->nt_unmap_view_of_section(process, remote_view);
        table->close_handle(section);
        return 23;
    }
    footless_log_event("remote_thread",
                       "\"operation\":\"create_remote_thread\","
                       "\"api\":\"%s\",\"target_pid\":%lu,"
                       "\"new_tid\":%lu,\"start_address\":\"0x%llx\","
                       "\"memory_backing\":\"pagefile_section\"",
                       FOOTLESS_API_LABEL("NtCreateThreadEx"),
                       (unsigned long)options->target_pid,
                       (unsigned long)result->new_tid,
                       (unsigned long long)(ULONG_PTR)remote_view);
    ok = wait_thread(table, thread, options->timeout_ms, &exit_code);
    result->exit_code = (int)exit_code;
    table->close_handle(thread);
    if (ok) {
        table->nt_unmap_view_of_section(process, remote_view);
        table->close_handle(section);
    } else {
        footless_log_event(
            "cleanup_deferred",
            "\"reason\":\"section thread termination unconfirmed; view "
            "retained until target exit\"");
    }
    result->ok = ok;
    return ok ? 0 : 24;
}

BOOL footless_inject(FOOTLESS_API_TABLE *table,
                     const FOOTLESS_INJECT_OPTIONS *options,
                     FOOTLESS_INJECT_RESULT *result_out) {
    HANDLE process = NULL;
    FOOTLESS_OBJECT_ATTRIBUTES attributes;
    FOOTLESS_CLIENT_ID client_id;
    WCHAR image[MAX_PATH];
    DWORD image_length = MAX_PATH;
    WCHAR full_dll[MAX_PATH];
    BOOL wow64 = FALSE;
    LONG status;
    int code;
    char image_escaped[MAX_PATH * 3];
    char dll_escaped[MAX_PATH * 3];
    DWORD access_mask = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                        PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                        PROCESS_VM_READ | SYNCHRONIZE;

    if (table == NULL || options == NULL || result_out == NULL ||
        options->dll_path == NULL || options->target_pid == 0U) {
        return FALSE;
    }
    ZeroMemory(result_out, sizeof(*result_out));
    result_out->target_pid = options->target_pid;
    result_out->target_tid = options->target_tid;

    ZeroMemory(&attributes, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    client_id.UniqueProcess = (HANDLE)(ULONG_PTR)options->target_pid;
    client_id.UniqueThread = NULL;
    status = table->nt_open_process(&process, access_mask, &attributes,
                                    &client_id);
    if (status < 0 || process == NULL) {
        log_error("open_process", status, GetLastError());
        result_out->last_status = status;
        return FALSE;
    }
    footless_log_event("process_open",
                       "\"operation\":\"open_process\",\"api\":\"%s\","
                       "\"source_pid\":%lu,\"target_pid\":%lu,"
                       "\"requested_access\":[\"PROCESS_CREATE_THREAD\","
                       "\"PROCESS_QUERY_INFORMATION\",\"PROCESS_VM_OPERATION\","
                       "\"PROCESS_VM_WRITE\",\"PROCESS_VM_READ\","
                       "\"SYNCHRONIZE\"],\"access_mask\":\"0x%lx\","
                       "\"ntstatus\":\"0x%08lx\"",
                       FOOTLESS_API_LABEL("NtOpenProcess"),
                       (unsigned long)GetCurrentProcessId(),
                       (unsigned long)options->target_pid,
                       (unsigned long)access_mask, (unsigned long)status);
    if (!table->query_full_process_image_name(process, 0U, image,
                                              &image_length)) {
        log_error("query_target_image", 0, GetLastError());
        table->close_handle(process);
        return FALSE;
    }
    image[image_length < MAX_PATH ? image_length : MAX_PATH - 1U] = L'\0';
    json_path(image, image_escaped, sizeof(image_escaped));
    if (!footless_target_name_allowed(image)) {
        footless_log_event("refused",
                           "\"reason\":\"target_not_in_lab_allowlist\","
                           "\"target_image\":\"%s\"",
                           image_escaped);
        table->close_handle(process);
        return FALSE;
    }
    if (!table->is_wow64_process(process, &wow64) || wow64) {
        log_error("target_architecture_check", 0, ERROR_NOT_SUPPORTED);
        table->close_handle(process);
        return FALSE;
    }
    {
        DWORD full_length =
            GetFullPathNameW(options->dll_path, MAX_PATH, full_dll, NULL);
        if (full_length == 0U || full_length >= MAX_PATH ||
            !footless_marker_name_allowed(full_dll)) {
            log_error("marker_dll_check", 0, ERROR_INVALID_PARAMETER);
            table->close_handle(process);
            return FALSE;
        }
    }
    if (GetFileAttributesW(full_dll) == INVALID_FILE_ATTRIBUTES) {
        log_error("marker_dll_missing", 0, ERROR_FILE_NOT_FOUND);
        table->close_handle(process);
        return FALSE;
    }
    json_path(full_dll, dll_escaped, sizeof(dll_escaped));
    footless_log_event("source_target",
                       "\"method\":\"%s\",\"target_pid\":%lu,"
                       "\"target_tid\":%lu,\"target_image\":\"%s\","
                       "\"marker_dll\":\"%s\",\"process_access_mask\":\"0x%lx\"",
                       footless_method_name(options->method),
                       (unsigned long)options->target_pid,
                       (unsigned long)options->target_tid, image_escaped,
                       dll_escaped, (unsigned long)access_mask);

    switch (options->method) {
        case FOOTLESS_METHOD_SECTION:
            code = section_flow(table, process, options, result_out);
            break;
        case FOOTLESS_METHOD_CRT:
        case FOOTLESS_METHOD_NT:
        case FOOTLESS_METHOD_STUB:
        case FOOTLESS_METHOD_APC: {
            FOOTLESS_INJECT_OPTIONS adjusted = *options;
            adjusted.dll_path = full_dll;
            code = common_dll_flow(table, process, &adjusted, result_out);
            break;
        }
        default:
            code = 2;
            break;
    }
    footless_log_event("result",
                       "\"method\":\"%s\",\"exit_code\":%d,"
                       "\"thread_apc_marker_counter\":0,"
                       "\"note\":\"ground truth must be read from marker.jsonl\"",
                       footless_method_name(options->method), code);
    table->close_handle(process);
    result_out->stage_code = (DWORD)code;
    result_out->ok = code == 0;
    return result_out->ok;
}
