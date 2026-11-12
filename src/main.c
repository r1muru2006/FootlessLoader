#include "hash.h"
#include "inject.h"
#include "log.h"
#include "ntapi.h"
#include "resolver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifndef FOOTLESS_DEFAULT_VARIANT
#define FOOTLESS_DEFAULT_VARIANT FOOTLESS_HASH_BASELINE
#endif

#ifndef FOOTLESS_DEFAULT_SEED_VALUE
#define FOOTLESS_DEFAULT_SEED_VALUE FOOTLESS_DEFAULT_SEED
#endif

#ifndef FOOTLESS_QUIET
static const char *const g_resolver_apis[] = {
    "RtlGetVersion",
    "NtOpenProcess",
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateThreadEx",
    "NtQueueApcThread",
    "NtCreateSection",
    "NtMapViewOfSection",
    "NtClose",
    "NtQueryInformationProcess",
};
#endif

#ifndef FOOTLESS_QUIET
static int run_variant(FOOTLESS_HASH_VARIANT variant, uint32_t seed) {
    size_t index;
    int failures = 0;

    printf("[variant] %s (seed=0x%08lx)\n",
           footless_hash_variant_name(variant), (unsigned long)seed);
    for (index = 0U;
         index < sizeof(g_resolver_apis) / sizeof(g_resolver_apis[0]);
         ++index) {
        void *address = NULL;
        FOOTLESS_RESOLVE_INFO info;
        uint32_t target_hash = footless_hash_for_variant(
            variant, "ntdll.dll", g_resolver_apis[index], seed);
        BOOL ok = footless_resolve_api_by_hash("ntdll.dll",
                                               g_resolver_apis[index], variant,
                                               seed, &address, &info);
        printf("  %-30s hash=0x%08lx status=%-12s address=%p\n",
               g_resolver_apis[index], (unsigned long)target_hash,
               footless_resolve_status_name(info.status), address);
        if (!ok || address == NULL ||
            strcmp(info.matched_name, g_resolver_apis[index]) != 0) {
            ++failures;
        }
    }
    return failures;
}

static int test_missing_hash(FOOTLESS_HASH_VARIANT variant, uint32_t seed) {
    void *address = NULL;
    FOOTLESS_RESOLVE_INFO info;
    uint32_t missing = UINT32_C(0xdeadbeef);
    BOOL ok = footless_resolve_export_by_hash(
        footless_module_by_hash(
            footless_hash_baseline("ntdll.dll", strlen("ntdll.dll"), seed),
            seed),
        "ntdll.dll", missing, variant, seed, &address, &info);
    printf("[negative] %-26s status=%-12s address=%p\n",
           footless_hash_variant_name(variant),
           footless_resolve_status_name(info.status), address);
    return ok || address != NULL ||
           info.status != FOOTLESS_RESOLVE_NOT_FOUND;
}
#endif

static int command_selftest(FOOTLESS_HASH_VARIANT variant, uint32_t seed) {
    int failures = 0;
    FOOTLESS_API_TABLE table;
    OSVERSIONINFOW version;
    LONG status;

#ifndef FOOTLESS_QUIET
    if (variant == FOOTLESS_HASH_VARIANT_COUNT) {
        for (variant = FOOTLESS_HASH_BASELINE;
             variant < FOOTLESS_HASH_VARIANT_COUNT;
             variant = (FOOTLESS_HASH_VARIANT)((int)variant + 1)) {
            failures += run_variant(variant, seed);
            failures += test_missing_hash(variant, seed);
        }
    } else {
        failures += run_variant(variant, seed);
        failures += test_missing_hash(variant, seed);
    }
#endif
    if (!footless_init_api_table(variant == FOOTLESS_HASH_VARIANT_COUNT
                                     ? FOOTLESS_DEFAULT_VARIANT
                                     : variant,
                                 seed, &table)) {
        fprintf(stderr, "[FAIL] API table initialization\n");
        ++failures;
    } else {
        ZeroMemory(&version, sizeof(version));
        version.dwOSVersionInfoSize = sizeof(version);
        status = table.rtl_get_version(&version);
        printf("[call] RtlGetVersion status=%ld version=%lu.%lu build=%lu\n",
               (long)status, (unsigned long)version.dwMajorVersion,
               (unsigned long)version.dwMinorVersion,
               (unsigned long)version.dwBuildNumber);
        printf("[call] API table entries resolved: %u\n",
               footless_api_table_size());
        if (status < 0) {
            ++failures;
        }
    }
    if (failures != 0) {
        fprintf(stderr, "[FAIL] resolver checks failed: %d\n", failures);
        return 1;
    }
    printf("[PASS] resolver and API table checks passed\n");
    return 0;
}

static int command_resolve(const char *module, const char *api,
                           FOOTLESS_HASH_VARIANT variant, uint32_t seed) {
    void *address = NULL;
    FOOTLESS_RESOLVE_INFO info;
    uint32_t hash = footless_hash_for_variant(variant, module, api, seed);
    BOOL ok = footless_resolve_api_by_hash(module, api, variant, seed,
                                           &address, &info);

    printf("variant=%s seed=0x%08lx module=%s api=%s hash=0x%08lx\n",
           footless_hash_variant_name(variant), (unsigned long)seed, module,
           api, (unsigned long)hash);
    printf("status=%s address=%p matched=%s rva=0x%lx ordinal=%u\n",
           footless_resolve_status_name(info.status), address,
           info.matched_name, (unsigned long)info.function_rva,
           (unsigned int)info.ordinal);
    return ok ? 0 : 1;
}

static int lab_gate(void) {
    const char *confirm = getenv("FOOTLESS_LAB_CONFIRM");
    WCHAR snapshot[256];
    DWORD length = GetEnvironmentVariableW(L"FOOTLESS_VM_SNAPSHOT", snapshot,
                                           256);

    if (confirm == NULL || strcmp(confirm, "1") != 0) {
        fprintf(stderr,
                "Refused: set FOOTLESS_LAB_CONFIRM=1 inside an isolated lab "
                "VM with a snapshot. See SAFETY.md.\n");
        return 0;
    }
    if (length == 0U || length >= 256U) {
        fprintf(stderr,
                "Refused: set FOOTLESS_VM_SNAPSHOT to the snapshot name. "
                "See SAFETY.md.\n");
        return 0;
    }
    return 1;
}

static uint32_t parse_seed(const char *text, uint32_t fallback) {
    char *end = NULL;
    unsigned long value;
    if (text == NULL) {
        return fallback;
    }
    value = strtoul(text, &end, 0);
    if (end == text || value > UINT32_MAX) {
        return fallback;
    }
    return (uint32_t)value;
}

static int command_inject(int argc, char **argv, FOOTLESS_HASH_VARIANT variant,
                          uint32_t seed) {
    FOOTLESS_INJECT_OPTIONS options;
    FOOTLESS_INJECT_RESULT result;
    FOOTLESS_API_TABLE table;
    const char *name = NULL;
    const char *dll_ascii = "footless_marker.dll";
    const char *run_id = "manual";
    const char *scenario = "inject";
    const char *log_path = "loader.jsonl";
    WCHAR dll_wide[MAX_PATH];
    DWORD pid = 0U;
    int index;

    ZeroMemory(&options, sizeof(options));
    options.timeout_ms = 5000U;
    options.method = FOOTLESS_METHOD_CRT;
    for (index = 0; index < argc; ++index) {
        const char *arg = argv[index];
        const char *value = index + 1 < argc ? argv[index + 1] : NULL;
        if (strcmp(arg, "--pid") == 0 && value != NULL) {
            pid = (DWORD)strtoul(value, NULL, 0);
            ++index;
        } else if (strcmp(arg, "--name") == 0 && value != NULL) {
            name = value;
            ++index;
        } else if (strcmp(arg, "--tid") == 0 && value != NULL) {
            options.target_tid = (DWORD)strtoul(value, NULL, 0);
            ++index;
        } else if (strcmp(arg, "--method") == 0 && value != NULL) {
            if (!footless_method_from_name(value, &options.method)) {
                fprintf(stderr, "unknown method: %s\n", value);
                return 2;
            }
            ++index;
        } else if (strcmp(arg, "--dll") == 0 && value != NULL) {
            dll_ascii = value;
            ++index;
        } else if (strcmp(arg, "--timeout") == 0 && value != NULL) {
            options.timeout_ms = (DWORD)strtoul(value, NULL, 0);
            ++index;
        } else if (strcmp(arg, "--run") == 0 && value != NULL) {
            run_id = value;
            ++index;
        } else if (strcmp(arg, "--scenario") == 0 && value != NULL) {
            scenario = value;
            ++index;
        } else if (strcmp(arg, "--log") == 0 && value != NULL) {
            log_path = value;
            ++index;
        } else if (strcmp(arg, "--variant") == 0 && value != NULL) {
            FOOTLESS_HASH_VARIANT parsed;
            if (!footless_hash_variant_from_name(value, &parsed)) {
                fprintf(stderr, "unknown variant: %s\n", value);
                return 2;
            }
            variant = parsed;
            ++index;
        } else if (strcmp(arg, "--seed") == 0 && value != NULL) {
            seed = parse_seed(value, seed);
            ++index;
        } else {
            fprintf(stderr, "unknown inject option: %s\n", arg);
            return 2;
        }
    }
    if (options.timeout_ms < 100U || options.timeout_ms > 60000U) {
        fprintf(stderr, "timeout must be 100..60000 ms\n");
        return 2;
    }
    if (!lab_gate()) {
        return 2;
    }
    if (!footless_init_api_table(variant, seed, &table)) {
        fprintf(stderr, "API table initialization failed\n");
        return 1;
    }
    if (pid == 0U && name != NULL) {
        WCHAR name_wide[256];
        if (MultiByteToWideChar(CP_UTF8, 0, name, -1, name_wide, 256) <= 0) {
            return 2;
        }
        pid = footless_find_process_by_name(name_wide, &table);
        if (pid == 0U) {
            fprintf(stderr, "process not found: %s\n", name);
            return 1;
        }
        printf("[+] %s -> PID %lu\n", name, (unsigned long)pid);
    }
    if (pid == 0U) {
        fprintf(stderr, "inject requires --pid or --name\n");
        return 2;
    }
    if (MultiByteToWideChar(CP_UTF8, 0, dll_ascii, -1, dll_wide, MAX_PATH) <=
        0) {
        return 2;
    }
    if (!footless_log_open(log_path, run_id, scenario)) {
        fprintf(stderr, "cannot open log: %s\n", log_path);
        return 1;
    }
    printf("[+] method=%s target=%lu variant=%s seed=0x%08lx log=%s\n",
           footless_method_name(options.method), (unsigned long)pid,
           footless_hash_variant_name(variant), (unsigned long)seed, log_path);
    options.target_pid = pid;
    options.dll_path = dll_wide;
    if (!footless_inject(&table, &options, &result)) {
        fprintf(stderr,
                "[FAIL] stage=%lu ntstatus=0x%08lx win32=%lu\n",
                (unsigned long)result.stage_code,
                (unsigned long)result.last_status,
                (unsigned long)result.last_error);
        footless_log_close();
        return 1;
    }
    printf("[PASS] method=%s target_pid=%lu new_tid=%lu exit_code=%d\n",
           footless_method_name(options.method),
           (unsigned long)result.target_pid, (unsigned long)result.new_tid,
           result.exit_code);
    if (options.method == FOOTLESS_METHOD_APC) {
        printf("[note] APC queue is an attempt; verify marker.jsonl for "
               "dispatch and TID.\n");
    }
    footless_log_close();
    return 0;
}

static void usage(void) {
    printf(
        "FootlessLoader - controlled API-hashing + NT API injection lab\n"
        "\n"
        "Usage:\n"
        "  footless_loader.exe selftest [--variant V|all] [--seed S]\n"
        "  footless_loader.exe resolve MODULE API [--variant V] [--seed S]\n"
        "  footless_loader.exe find --name IMAGE.EXE [--variant V] [--seed S]\n"
        "  footless_loader.exe inject --pid N | --name IMAGE.EXE\n"
        "        [--tid N] [--method crt|nt|stub|apc|section]\n"
        "        [--dll footless_marker.dll] [--timeout MS]\n"
        "        [--run ID] [--scenario ID] [--log loader.jsonl]\n"
        "        [--variant baseline|seeded|module-api] [--seed S]\n"
        "\n"
        "V of --variant: baseline | seeded | module-api | all\n"
        "Injection requires FOOTLESS_LAB_CONFIRM=1 and "
        "FOOTLESS_VM_SNAPSHOT=<snapshot>.\n");
}

int main(int argc, char **argv) {
    FOOTLESS_HASH_VARIANT variant = FOOTLESS_DEFAULT_VARIANT;
    uint32_t seed = FOOTLESS_DEFAULT_SEED_VALUE;
    const char *command = argc > 1 ? argv[1] : "selftest";
    int index;

    for (index = 1; index < argc; ++index) {
        const char *value = index + 1 < argc ? argv[index + 1] : NULL;
        if (strcmp(argv[index], "--variant") == 0 && value != NULL) {
            if (strcmp(value, "all") == 0) {
                variant = FOOTLESS_HASH_VARIANT_COUNT;
            } else if (!footless_hash_variant_from_name(value, &variant)) {
                fprintf(stderr, "unknown variant: %s\n", value);
                return 2;
            }
        } else if (strcmp(argv[index], "--seed") == 0 && value != NULL) {
            seed = parse_seed(value, seed);
        } else if (strcmp(argv[index], "--help") == 0) {
            usage();
            return 0;
        }
    }
    if (strcmp(command, "selftest") == 0) {
        return command_selftest(variant, seed);
    }
    if (strcmp(command, "resolve") == 0) {
        if (argc < 4) {
            usage();
            return 2;
        }
        return command_resolve(argv[2], argv[3],
                               variant == FOOTLESS_HASH_VARIANT_COUNT
                                   ? FOOTLESS_DEFAULT_VARIANT
                                   : variant,
                               seed);
    }
    if (strcmp(command, "find") == 0) {
        const char *name = NULL;
        FOOTLESS_API_TABLE table;
        WCHAR name_wide[256];
        DWORD pid;
        for (index = 2; index < argc; ++index) {
            if (strcmp(argv[index], "--name") == 0 && index + 1 < argc) {
                name = argv[++index];
            }
        }
        if (name == NULL) {
            fprintf(stderr, "find requires --name IMAGE.EXE\n");
            return 2;
        }
        if (!footless_init_api_table(
                variant == FOOTLESS_HASH_VARIANT_COUNT
                    ? FOOTLESS_DEFAULT_VARIANT
                    : variant,
                seed, &table)) {
            return 1;
        }
        if (MultiByteToWideChar(CP_UTF8, 0, name, -1, name_wide, 256) <= 0) {
            return 2;
        }
        pid = footless_find_process_by_name(name_wide, &table);
        if (pid == 0U) {
            fprintf(stderr, "not found: %s\n", name);
            return 1;
        }
        printf("%lu\n", (unsigned long)pid);
        return 0;
    }
    if (strcmp(command, "inject") == 0) {
        return command_inject(argc - 2, argv + 2,
                              variant == FOOTLESS_HASH_VARIANT_COUNT
                                  ? FOOTLESS_DEFAULT_VARIANT
                                  : variant,
                              seed);
    }
    usage();
    return 2;
}
