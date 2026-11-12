#ifndef FOOTLESS_HASH_H
#define FOOTLESS_HASH_H

#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

/*
 * Three controlled resolver variants used by the lab.  They differ only in
 * how the lookup key is derived; every variant walks the same PE export
 * table and returns the same kind of function address.
 *
 *   baseline     FNV-1a over the API name
 *   seeded       rotate/xor/add over the API name, mixed with a seed
 *   module-api   rotate/xor/add over "module:api", mixed with a seed
 *
 * The variants exist so the detector can be measured against changing
 * constants and ordering instead of one fixed hash value.
 */
typedef enum FOOTLESS_HASH_VARIANT {
    FOOTLESS_HASH_BASELINE = 0,
    FOOTLESS_HASH_SEEDED = 1,
    FOOTLESS_HASH_MODULE_API = 2,
    FOOTLESS_HASH_VARIANT_COUNT = 3
} FOOTLESS_HASH_VARIANT;

#define FOOTLESS_DEFAULT_SEED UINT32_C(0x13579bdf)

uint32_t footless_hash_baseline(const char *text, size_t length, uint32_t seed);
uint32_t footless_hash_seeded(const char *text, size_t length, uint32_t seed);
uint32_t footless_hash_module_api(const char *module_name, size_t module_length,
                                  const char *api_name, size_t api_length,
                                  uint32_t seed);

/* Case-insensitive wide hash used only to locate a module in the PEB list. */
uint32_t footless_hash_wide_ci(const wchar_t *text, uint32_t seed);

uint32_t footless_hash_for_variant(FOOTLESS_HASH_VARIANT variant,
                                  const char *module_name,
                                  const char *api_name,
                                  uint32_t seed);
const char *footless_hash_variant_name(FOOTLESS_HASH_VARIANT variant);
int footless_hash_variant_from_name(const char *name,
                                    FOOTLESS_HASH_VARIANT *variant_out);

#endif
