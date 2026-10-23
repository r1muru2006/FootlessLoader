#include "hash.h"

#include <string.h>

static uint32_t rotate_left32(uint32_t value, unsigned int count) {
    count &= 31U;
    if (count == 0U) {
        return value;
    }
    return (value << count) | (value >> (32U - count));
}

static uint32_t feed_rotate_xor(uint32_t state, unsigned char byte) {
    state = rotate_left32(state, 5U);
    state ^= (uint32_t)byte;
    state += UINT32_C(0x9e3779b9);
    return state;
}

uint32_t footless_hash_baseline(const char *text, size_t length, uint32_t seed) {
    uint32_t state = UINT32_C(0x811c9dc5) ^ seed;
    size_t index;

    if (text == NULL) {
        return 0U;
    }
    for (index = 0U; index < length; ++index) {
        state ^= (uint32_t)(unsigned char)text[index];
        state *= UINT32_C(0x01000193);
    }
    return state;
}

uint32_t footless_hash_seeded(const char *text, size_t length, uint32_t seed) {
    uint32_t state = UINT32_C(0xa5a5a5a5) ^ seed;
    size_t index;

    if (text == NULL) {
        return 0U;
    }
    for (index = 0U; index < length; ++index) {
        state = feed_rotate_xor(state, (unsigned char)text[index]);
    }
    return state;
}

uint32_t footless_hash_module_api(const char *module_name, size_t module_length,
                                  const char *api_name, size_t api_length,
                                  uint32_t seed) {
    uint32_t state = UINT32_C(0xa5a5a5a5) ^ seed;
    size_t index;

    if (module_name == NULL || api_name == NULL) {
        return 0U;
    }
    for (index = 0U; index < module_length; ++index) {
        state = feed_rotate_xor(state, (unsigned char)module_name[index]);
    }
    state = feed_rotate_xor(state, (unsigned char)':');
    for (index = 0U; index < api_length; ++index) {
        state = feed_rotate_xor(state, (unsigned char)api_name[index]);
    }
    return state;
}

uint32_t footless_hash_for_variant(FOOTLESS_HASH_VARIANT variant,
                                  const char *module_name,
                                  const char *api_name,
                                  uint32_t seed) {
    size_t api_length;

    if (api_name == NULL) {
        return 0U;
    }
    api_length = strlen(api_name);
    switch (variant) {
        case FOOTLESS_HASH_BASELINE:
            return footless_hash_baseline(api_name, api_length, seed);
        case FOOTLESS_HASH_SEEDED:
            return footless_hash_seeded(api_name, api_length, seed);
        case FOOTLESS_HASH_MODULE_API:
            if (module_name == NULL) {
                return 0U;
            }
            return footless_hash_module_api(module_name, strlen(module_name),
                                            api_name, api_length, seed);
        default:
            return 0U;
    }
}

const char *footless_hash_variant_name(FOOTLESS_HASH_VARIANT variant) {
    switch (variant) {
        case FOOTLESS_HASH_BASELINE:
            return "baseline-api";
        case FOOTLESS_HASH_SEEDED:
            return "seeded-rotate-xor";
        case FOOTLESS_HASH_MODULE_API:
            return "module-api-rotate-xor";
        default:
            return "unknown";
    }
}
