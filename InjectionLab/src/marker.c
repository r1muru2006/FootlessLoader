#include "lab.h"
/* No logging, loader calls, worker threads, or synchronization under loader lock. */
BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)module;(void)reason;(void)reserved;
    return TRUE;
}
__declspec(dllexport) DWORD WINAPI Nt230DllMarker(LPVOID ignored) {
    (void)ignored;
    return lab_env_marker("dll_marker");
}
