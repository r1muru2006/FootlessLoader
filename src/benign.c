#include <windows.h>
#include <stdio.h>
#include <string.h>

/*
 * Benign control binary for the detector's negative class.
 * Ordinary static imports, a local allocation, a temp-file write and a
 * short sleep.  No dynamic resolution, no cross-process operations.
 */
int main(void) {
    char path[MAX_PATH];
    char buffer[256];
    DWORD written = 0U;
    LPVOID memory;
    DWORD temp_length = GetTempPathA(MAX_PATH, path);
    HANDLE file;

    printf("benign pid=%lu tid=%lu\n", (unsigned long)GetCurrentProcessId(),
           (unsigned long)GetCurrentThreadId());
    memory = VirtualAlloc(NULL, 4096U, MEM_RESERVE | MEM_COMMIT,
                          PAGE_READWRITE);
    if (memory != NULL) {
        strcpy((char *)memory, "benign local buffer");
        VirtualProtect(memory, 4096U, PAGE_READONLY, NULL);
        VirtualFree(memory, 0U, MEM_RELEASE);
    }
    if (temp_length > 0U && temp_length + 16U < MAX_PATH) {
        strcpy(path + temp_length, "footless_benign.tmp");
        file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_TEMPORARY, NULL);
        if (file != INVALID_HANDLE_VALUE) {
            strcpy(buffer, "harmless control write\n");
            WriteFile(file, buffer, (DWORD)strlen(buffer), &written, NULL);
            CloseHandle(file);
            DeleteFileA(path);
        }
    }
    Sleep(200U);
    printf("benign done\n");
    return 0;
}
