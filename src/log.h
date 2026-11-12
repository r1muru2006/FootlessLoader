#ifndef FOOTLESS_LOG_H
#define FOOTLESS_LOG_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stddef.h>

/*
 * Lab telemetry log.  Loader events go to loader.jsonl (detector input),
 * marker ground truth goes to marker.jsonl (never detector input).
 * Both are newline-delimited JSON with the same envelope fields.
 */
BOOL footless_log_open(const char *path, const char *run_id,
                       const char *scenario_id);
void footless_log_close(void);
void footless_log_event(const char *event, const char *fmt, ...);
void footless_log_marker(const char *path, const char *run_id,
                         const char *scenario_id, const char *kind);

void footless_json_escape(const char *input, char *output, size_t capacity);
void footless_json_escape_wide(const wchar_t *input, char *output,
                               size_t capacity);

#endif
