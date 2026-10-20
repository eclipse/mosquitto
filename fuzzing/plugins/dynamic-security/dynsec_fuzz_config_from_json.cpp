#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>

extern "C" {
#include "/src/mosquitto/plugins/dynamic-security/dynamic_security.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Data == nullptr || Size == 0) {
        return 0;
    }

    // Cap the amount of data we copy to prevent large allocations and to keep each
    // invocation bounded. 64 KiB is a reasonable limit for fuzzing JSON parsing here.
    const size_t MAX_ALLOC = 64 * 1024; // 64 KiB
    size_t use_size = Size;
    if (use_size > MAX_ALLOC) use_size = MAX_ALLOC;

    char *json = (char *)malloc(use_size + 1);
    if (json == nullptr) return 0;

    memcpy(json, Data, use_size);
    json[use_size] = '\0';

    // Prepare a minimal dynsec__data structure. Zero-initialized to keep pointers NULL.
    struct dynsec__data data;
    memset(&data, 0, sizeof(data));

    // Call the target function with our fuzzed JSON string.
    (void)dynsec__config_from_json(&data, json);

    // IMPORTANT: cleanup order matters.
    // Groups reference clients (group->clientlist -> client). If clients are freed
    // before groups, groups cleanup will access freed client memory and crash.
    // Therefore, remove/cleanup groups first, then clients, then roles/kicklist.
    dynsec_groups__cleanup(&data);
    dynsec_clients__cleanup(&data);
    dynsec_roles__cleanup(&data);
    dynsec_kicklist__cleanup(&data);

    // Ensure any remaining top-level char* members are freed if set by the plugin.
    // The cleanup functions above should free allocated internals, but guard here
    // in case config_file/password_init_file were allocated separately and not freed.
    // If these pointers point into our 'json' buffer, do NOT free them separately
    // (they will be freed when we free 'json' below). Detect that by checking
    // whether the pointer lies within the json buffer range.
    if (data.config_file) {
        char *p = data.config_file;
        if (p < json || p >= json + use_size + 1) {
            free(data.config_file);
        }
        data.config_file = NULL;
    }
    if (data.password_init_file) {
        char *p = data.password_init_file;
        if (p < json || p >= json + use_size + 1) {
            free(data.password_init_file);
        }
        data.password_init_file = NULL;
    }

    // Now free our temporary JSON buffer. It must be freed after cleanup to avoid
    // use-after-free in cleanup routines that may reference substrings inside it.
    free(json);

    return 0;
}