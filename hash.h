#ifndef FOOTLESS_HASH_H
#define FOOTLESS_HASH_H

#include <stddef.h>
#include <stdint.h>

/*
 * Three controlled, benign resolver variants used by the lab.
 * They differ only in how the lookup key is hashed; all variants walk
 * the same PE export table and return the same kind of function address.
 */
typedef enum FOOTLESS_HASH_VARIANT {
    FOOTLESS_HASH_BASELINE = 0,
    FOOTLESS_HASH_SEEDED = 1,
    FOOTLESS_HASH_MODULE_API = 2
} FOOTLESS_HASH_VARIANT;

uint32_t footless_hash_baseline(const char *text, size_t length, uint32_t seed);
uint32_t footless_hash_seeded(const char *text, size_t length, uint32_t seed);
uint32_t footless_hash_module_api(const char *module_name, size_t module_length,
                                  const char *api_name, size_t api_length,
                                  uint32_t seed);

uint32_t footless_hash_for_variant(FOOTLESS_HASH_VARIANT variant,
                                  const char *module_name,
                                  const char *api_name,
                                  uint32_t seed);
const char *footless_hash_variant_name(FOOTLESS_HASH_VARIANT variant);

#endif
