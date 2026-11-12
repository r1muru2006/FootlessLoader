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

uint32_t footless_hash_wide_ci(const wchar_t *text, uint32_t seed) {
    uint32_t state = UINT32_C(0x811c9dc5) ^ seed;
    size_t index;

    if (text == NULL) {
        return 0U;
    }
    for (index = 0U; text[index] != L'\0'; ++index) {
        wchar_t ch = text[index];
        unsigned char byte;
        if (ch >= L'A' && ch <= L'Z') {
            ch = (wchar_t)(ch - L'A' + L'a');
        }
        byte = (unsigned char)((unsigned int)ch & 0xffU);
        state ^= (uint32_t)byte;
        state *= UINT32_C(0x01000193);
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

int footless_hash_variant_from_name(const char *name,
                                    FOOTLESS_HASH_VARIANT *variant_out) {
    int index;

    if (name == NULL || variant_out == NULL) {
        return 0;
    }
    if (strcmp(name, "baseline") == 0 || strcmp(name, "baseline-api") == 0) {
        *variant_out = FOOTLESS_HASH_BASELINE;
        return 1;
    }
    if (strcmp(name, "seeded") == 0 || strcmp(name, "seeded-rotate-xor") == 0) {
        *variant_out = FOOTLESS_HASH_SEEDED;
        return 1;
    }
    if (strcmp(name, "module-api") == 0 ||
        strcmp(name, "module_api") == 0 ||
        strcmp(name, "module-api-rotate-xor") == 0) {
        *variant_out = FOOTLESS_HASH_MODULE_API;
        return 1;
    }
    for (index = 0; index < 3; ++index) {
        char digit[2];
        digit[0] = (char)('0' + index);
        digit[1] = '\0';
        if (strcmp(name, digit) == 0) {
            *variant_out = (FOOTLESS_HASH_VARIANT)index;
            return 1;
        }
    }
    return 0;
}
