#ifndef FOOTLESS_NTAPI_H
#define FOOTLESS_NTAPI_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "resolver.h"

typedef LONG (NTAPI *FOOTLESS_RTL_GET_VERSION_FN)(LPOSVERSIONINFOW version_info);
typedef LONG (NTAPI *FOOTLESS_NT_CLOSE_FN)(HANDLE handle);
typedef LONG (NTAPI *FOOTLESS_NT_QUERY_INFORMATION_PROCESS_FN)(
    HANDLE process_handle, ULONG information_class, PVOID information,
    ULONG information_length, PULONG return_length);

typedef struct FOOTLESS_NTAPI_TABLE {
    FOOTLESS_RTL_GET_VERSION_FN rtl_get_version;
    FOOTLESS_NT_CLOSE_FN nt_close;
    FOOTLESS_NT_QUERY_INFORMATION_PROCESS_FN nt_query_information_process;
} FOOTLESS_NTAPI_TABLE;

BOOL footless_init_ntapi_table(FOOTLESS_HASH_VARIANT variant,
                               uint32_t seed,
                               FOOTLESS_NTAPI_TABLE *table_out);

#endif
