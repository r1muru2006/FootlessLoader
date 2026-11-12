#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static char g_path[MAX_PATH];
static char g_run[128];
static char g_scenario[128];
static BOOL g_open = FALSE;

void footless_json_escape(const char *input, char *output, size_t capacity) {
    size_t used = 0U;
    size_t index;

    if (output == NULL || capacity == 0U) {
        return;
    }
    if (input == NULL) {
        output[0] = '\0';
        return;
    }
    for (index = 0U; input[index] != '\0' && used + 7U < capacity; ++index) {
        unsigned char ch = (unsigned char)input[index];
        if (ch == '"' || ch == '\\') {
            output[used++] = '\\';
            output[used++] = (char)ch;
        } else if (ch < 0x20U) {
            used += (size_t)snprintf(output + used, capacity - used,
                                     "\\u%04x", (unsigned int)ch);
        } else {
            output[used++] = (char)ch;
        }
    }
    output[used] = '\0';
}

void footless_json_escape_wide(const wchar_t *input, char *output,
                               size_t capacity) {
    char utf8[MAX_PATH * 4];
    int length;

    if (output == NULL || capacity == 0U) {
        return;
    }
    output[0] = '\0';
    if (input == NULL) {
        return;
    }
    length = WideCharToMultiByte(CP_UTF8, 0, input, -1, utf8,
                                 (int)sizeof(utf8), NULL, NULL);
    if (length <= 0) {
        return;
    }
    footless_json_escape(utf8, output, capacity);
}

static void append_line(const char *path, const char *line, DWORD length) {
    HANDLE file;
    DWORD written = 0U;

    if (path == NULL || line == NULL || length == 0U) {
        return;
    }
    file = CreateFileA(path, FILE_APPEND_DATA,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    if (!WriteFile(file, line, length, &written, NULL) || written != length) {
        /* Best effort: telemetry loss is reported by the runbook check. */
    }
    FlushFileBuffers(file);
    CloseHandle(file);
}

BOOL footless_log_open(const char *path, const char *run_id,
                       const char *scenario_id) {
    if (path == NULL || path[0] == '\0') {
        return FALSE;
    }
    strncpy(g_path, path, sizeof(g_path) - 1U);
    g_path[sizeof(g_path) - 1U] = '\0';
    if (run_id != NULL) {
        strncpy(g_run, run_id, sizeof(g_run) - 1U);
        g_run[sizeof(g_run) - 1U] = '\0';
    } else {
        g_run[0] = '\0';
    }
    if (scenario_id != NULL) {
        strncpy(g_scenario, scenario_id, sizeof(g_scenario) - 1U);
        g_scenario[sizeof(g_scenario) - 1U] = '\0';
    } else {
        g_scenario[0] = '\0';
    }
    g_open = TRUE;
    return TRUE;
}

void footless_log_close(void) {
    g_open = FALSE;
}

void footless_log_event(const char *event, const char *fmt, ...) {
    char detail[8192];
    char run[160];
    char scenario[160];
    char event_escaped[160];
    char line[9000];
    SYSTEMTIME now;
    va_list args;
    int length;

    if (!g_open || event == NULL) {
        return;
    }
    detail[0] = '\0';
    if (fmt != NULL) {
        va_start(args, fmt);
        vsnprintf(detail, sizeof(detail), fmt, args);
        va_end(args);
        detail[sizeof(detail) - 1U] = '\0';
    }
    footless_json_escape(g_run, run, sizeof(run));
    footless_json_escape(g_scenario, scenario, sizeof(scenario));
    footless_json_escape(event, event_escaped, sizeof(event_escaped));
    GetSystemTime(&now);
    length = snprintf(
        line, sizeof(line),
        "{\"utc\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\","
        "\"tick_ms\":%llu,\"run_id\":\"%s\",\"scenario_id\":\"%s\","
        "\"pid\":%lu,\"tid\":%lu,\"event\":\"%s\"%s}\n",
        (unsigned int)now.wYear, (unsigned int)now.wMonth,
        (unsigned int)now.wDay, (unsigned int)now.wHour,
        (unsigned int)now.wMinute, (unsigned int)now.wSecond,
        (unsigned int)now.wMilliseconds,
        (unsigned long long)GetTickCount64(), run, scenario,
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(), event_escaped,
        detail[0] == '\0' ? "" : ",");
    if (length <= 0 || length >= (int)sizeof(line)) {
        return;
    }
    if (detail[0] != '\0') {
        /* detail is already a JSON fragment without braces. */
        char fixed[9000];
        length = snprintf(fixed, sizeof(fixed),
                          "{\"utc\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\","
                          "\"tick_ms\":%llu,\"run_id\":\"%s\","
                          "\"scenario_id\":\"%s\",\"pid\":%lu,\"tid\":%lu,"
                          "\"event\":\"%s\",%s}\n",
                          (unsigned int)now.wYear, (unsigned int)now.wMonth,
                          (unsigned int)now.wDay, (unsigned int)now.wHour,
                          (unsigned int)now.wMinute, (unsigned int)now.wSecond,
                          (unsigned int)now.wMilliseconds,
                          (unsigned long long)GetTickCount64(), run, scenario,
                          (unsigned long)GetCurrentProcessId(),
                          (unsigned long)GetCurrentThreadId(), event_escaped,
                          detail);
        if (length > 0 && length < (int)sizeof(fixed)) {
            append_line(g_path, fixed, (DWORD)length);
        }
        return;
    }
    append_line(g_path, line, (DWORD)length);
}

void footless_log_marker(const char *path, const char *run_id,
                         const char *scenario_id, const char *kind) {
    char line[2048];
    char run[160];
    char scenario[160];
    char kind_escaped[160];
    char process_image[MAX_PATH];
    char image_escaped[MAX_PATH * 2];
    SYSTEMTIME now;
    int length;

    GetModuleFileNameA(NULL, process_image, sizeof(process_image));
    process_image[sizeof(process_image) - 1U] = '\0';
    footless_json_escape(run_id != NULL ? run_id : "", run, sizeof(run));
    footless_json_escape(scenario_id != NULL ? scenario_id : "", scenario,
                         sizeof(scenario));
    footless_json_escape(kind != NULL ? kind : "marker", kind_escaped,
                         sizeof(kind_escaped));
    footless_json_escape(process_image, image_escaped, sizeof(image_escaped));
    GetSystemTime(&now);
    length = snprintf(
        line, sizeof(line),
        "{\"utc\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\","
        "\"tick_ms\":%llu,\"run_id\":\"%s\",\"scenario_id\":\"%s\","
        "\"pid\":%lu,\"tid\":%lu,\"image\":\"%s\",\"event\":\"marker\","
        "\"kind\":\"%s\"}\n",
        (unsigned int)now.wYear, (unsigned int)now.wMonth,
        (unsigned int)now.wDay, (unsigned int)now.wHour,
        (unsigned int)now.wMinute, (unsigned int)now.wSecond,
        (unsigned int)now.wMilliseconds,
        (unsigned long long)GetTickCount64(), run, scenario,
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(), image_escaped, kind_escaped);
    if (length > 0 && length < (int)sizeof(line)) {
        append_line(path, line, (DWORD)length);
    }
}
