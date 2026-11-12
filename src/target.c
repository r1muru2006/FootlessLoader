#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static void sibling_path(const wchar_t *name, wchar_t *out, size_t capacity) {
    DWORD length = GetModuleFileNameW(NULL, out, (DWORD)capacity);
    wchar_t *slash;
    if (length == 0U || length >= capacity) {
        out[0] = L'\0';
        return;
    }
    slash = wcsrchr(out, L'\\');
    if (slash == NULL) {
        out[0] = L'\0';
        return;
    }
    if ((size_t)(slash - out) + 1U + wcslen(name) >= capacity) {
        out[0] = L'\0';
        return;
    }
    wcscpy(slash + 1, name);
}

int main(int argc, char **argv) {
    const char *run_id = argc > 1 ? argv[1] : "manual";
    unsigned long seconds = argc > 2 ? strtoul(argv[2], NULL, 10) : 30UL;
    int self_dll = argc > 3 && strcmp(argv[3], "selfdll") == 0;
    char marker_path[MAX_PATH];
    wchar_t marker_wide[MAX_PATH];
    wchar_t dll_wide[MAX_PATH];
    DWORD marker_length;
    ULONGLONG deadline;

    if (seconds < 2UL || seconds > 3600UL) {
        fprintf(stderr, "usage: footless_target.exe RUN_ID SECONDS [selfdll]\n");
        return 2;
    }
    marker_length = GetEnvironmentVariableA("FOOTLESS_MARKER_LOG", marker_path,
                                            sizeof(marker_path));
    if (marker_length == 0U || marker_length >= sizeof(marker_path)) {
        strncpy(marker_path, "marker.jsonl", sizeof(marker_path) - 1U);
        marker_path[sizeof(marker_path) - 1U] = '\0';
    }
    if (MultiByteToWideChar(CP_UTF8, 0, marker_path, -1, marker_wide,
                            MAX_PATH) <= 0) {
        return 2;
    }
    SetEnvironmentVariableW(L"FOOTLESS_RUN_ID", L"");
    {
        wchar_t run_wide[128];
        if (MultiByteToWideChar(CP_UTF8, 0, run_id, -1, run_wide, 128) > 0) {
            SetEnvironmentVariableW(L"FOOTLESS_RUN_ID", run_wide);
        }
    }
    SetEnvironmentVariableW(L"FOOTLESS_MARKER_LOG", marker_wide);
    SetEnvironmentVariableW(L"FOOTLESS_SCENARIO", L"target");
    printf("READY run=%s pid=%lu tid=%lu seconds=%lu\n", run_id,
           (unsigned long)GetCurrentProcessId(),
           (unsigned long)GetCurrentThreadId(), seconds);
    fflush(stdout);

    if (self_dll) {
        sibling_path(L"footless_marker.dll", dll_wide, MAX_PATH);
        if (dll_wide[0] != L'\0') {
            HMODULE module = LoadLibraryW(dll_wide);
            printf("SELF_DLL base=%p\n", (void *)module);
            fflush(stdout);
            if (module != NULL) {
                Sleep(200);
                FreeLibrary(module);
            }
        } else {
            fprintf(stderr, "marker DLL path unavailable\n");
        }
    }

    deadline = GetTickCount64() + (ULONGLONG)seconds * 1000ULL;
    while (GetTickCount64() < deadline) {
        /* Alertable so the APC lab method can dispatch a queued callback. */
        SleepEx(25U, TRUE);
    }
    printf("DONE run=%s pid=%lu\n", run_id,
           (unsigned long)GetCurrentProcessId());
    fflush(stdout);
    return 0;
}
