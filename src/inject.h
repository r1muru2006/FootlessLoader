#ifndef FOOTLESS_INJECT_H
#define FOOTLESS_INJECT_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "ntapi.h"

/*
 * Controlled lab methods.  Every method ends in a benign marker DLL
 * whose DllMain writes marker.jsonl.  No arbitrary shellcode, no C2,
 * no credential access, no persistence.
 */
typedef enum FOOTLESS_INJECT_METHOD {
    FOOTLESS_METHOD_CRT = 0,
    FOOTLESS_METHOD_NT,
    FOOTLESS_METHOD_STUB,
    FOOTLESS_METHOD_APC,
    FOOTLESS_METHOD_SECTION,
    FOOTLESS_METHOD_COUNT
} FOOTLESS_INJECT_METHOD;

typedef struct FOOTLESS_INJECT_OPTIONS {
    DWORD target_pid;
    DWORD target_tid;      /* 0 => pick the first target thread for APC */
    FOOTLESS_INJECT_METHOD method;
    const wchar_t *dll_path;
    DWORD timeout_ms;
} FOOTLESS_INJECT_OPTIONS;

typedef struct FOOTLESS_INJECT_RESULT {
    BOOL ok;
    DWORD stage_code;
    DWORD target_pid;
    DWORD target_tid;
    DWORD new_tid;
    LONG last_status;
    DWORD last_error;
    int exit_code;
} FOOTLESS_INJECT_RESULT;

const char *footless_method_name(FOOTLESS_INJECT_METHOD method);
int footless_method_from_name(const char *name,
                              FOOTLESS_INJECT_METHOD *method_out);

BOOL footless_inject(FOOTLESS_API_TABLE *table,
                     const FOOTLESS_INJECT_OPTIONS *options,
                     FOOTLESS_INJECT_RESULT *result_out);

/* Safety rail shared by CLI and docs: only the lab target is accepted. */
BOOL footless_target_name_allowed(const wchar_t *image_path);
BOOL footless_marker_name_allowed(const wchar_t *dll_path);

#endif
