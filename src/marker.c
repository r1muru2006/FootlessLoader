#include "log.h"

#include <string.h>

/*
 * Benign marker DLL.  It writes one JSON line per load: the current PID
 * and TID prove in which process/thread context the loader acted.
 *
 * DllMain does a small file append on DLL_PROCESS_ATTACH for lab
 * simplicity.  Real DLLs should not perform I/O under the loader lock;
 * see docs/DESIGN.md "Limitations".  The exported FootlessMarker is
 * provided for a separate remote-thread phase if a runbook needs it.
 */

static void marker_from_environment(const char *kind) {
    WCHAR wide_path[MAX_PATH];
    WCHAR wide_run[128];
    WCHAR wide_scenario[128];
    char path[MAX_PATH * 3];
    char run[128 * 3];
    char scenario[128 * 3];
    DWORD path_length;
    DWORD run_length;
    DWORD scenario_length;

    path_length = GetEnvironmentVariableW(L"FOOTLESS_MARKER_LOG", wide_path,
                                          MAX_PATH);
    if (path_length == 0U || path_length >= MAX_PATH ||
        WideCharToMultiByte(CP_UTF8, 0, wide_path, -1, path, sizeof(path),
                            NULL, NULL) <= 0) {
        return;
    }
    run_length = GetEnvironmentVariableW(L"FOOTLESS_RUN_ID", wide_run, 128);
    if (run_length == 0U || run_length >= 128 ||
        WideCharToMultiByte(CP_UTF8, 0, wide_run, -1, run, sizeof(run), NULL,
                            NULL) <= 0) {
        strncpy(run, "unknown", sizeof(run) - 1U);
        run[sizeof(run) - 1U] = '\0';
    }
    scenario_length = GetEnvironmentVariableW(L"FOOTLESS_SCENARIO",
                                              wide_scenario, 128);
    if (scenario_length == 0U || scenario_length >= 128 ||
        WideCharToMultiByte(CP_UTF8, 0, wide_scenario, -1, scenario,
                            sizeof(scenario), NULL, NULL) <= 0) {
        strncpy(scenario, "unknown", sizeof(scenario) - 1U);
        scenario[sizeof(scenario) - 1U] = '\0';
    }
    footless_log_marker(path, run, scenario, kind);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        marker_from_environment("dll_attach");
    }
    return TRUE;
}

__declspec(dllexport) DWORD WINAPI FootlessMarker(LPVOID ignored) {
    (void)ignored;
    marker_from_environment("export_call");
    return 0;
}
