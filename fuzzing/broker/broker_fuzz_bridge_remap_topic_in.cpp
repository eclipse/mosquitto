#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

// Include project headers (absolute paths from the workspace).
// Wrap C headers in extern "C" so C++ compilation uses correct C linkage.
extern "C" {
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
#include "/src/mosquitto/lib/mosquitto_internal.h"
#include "/src/mosquitto/include/mosquitto/libcommon_memory.h"
#include "/src/mosquitto/include/mosquitto/libcommon_topic.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0) return 0;

    // Simple deterministic parser of the input buffer into several NUL-terminated strings
    // and an enum value for direction. We consume bytes from Data sequentially.
    size_t idx = 0;
    auto remaining = [&](void)->size_t { return (idx < Size) ? (Size - idx) : 0; };

    auto take_len = [&](size_t maxlen)->size_t {
        if(remaining() == 0) return 0;
        // Use next byte to determine a requested length (bounded by available data and maxlen).
        unsigned char b = Data[idx++];
        size_t len = (size_t)(b) % (maxlen + 1);
        if(len > remaining()) len = remaining();
        return len;
    };

    auto take_cstr = [&](size_t maxlen)->char* {
        size_t len = take_len(maxlen);
        // If no data, return an empty allocated string (function expects valid C-string pointers).
        if(len == 0){
            char *s = (char*)malloc(1);
            if(s) s[0] = '\0';
            return s;
        }
        char *s = (char*)malloc(len + 1);
        if(!s) return nullptr;
        memcpy(s, Data + idx, len);
        s[len] = '\0';
        idx += len;
        return s;
    };

    // Partition input into: initial topic, remote_topic (subscription), remote_prefix, local_prefix, and a direction byte.
    // maxlen chosen to be reasonable to avoid overly large allocations.
    const size_t kMaxPiece = 4096;

    char *initial_topic = take_cstr(kMaxPiece);
    char *remote_topic  = take_cstr(kMaxPiece);
    char *remote_prefix = take_cstr(kMaxPiece);
    char *local_prefix  = take_cstr(kMaxPiece);

    // Direction byte: if available, use it; otherwise default to bd_in.
    enum mosquitto__bridge_direction dir = bd_in;
    if(remaining() > 0){
        unsigned char b = Data[idx++];
        dir = (b % 3 == 0) ? bd_out : ((b % 3 == 1) ? bd_in : bd_both);
    }

    // Ensure we have at least an empty topic string
    if(!initial_topic){
        initial_topic = (char*)malloc(1);
        if(initial_topic) initial_topic[0] = '\0';
    }
    if(!remote_topic){
        remote_topic = (char*)malloc(1);
        if(remote_topic) remote_topic[0] = '\0';
    }
    // Note: remote_prefix/local_prefix may be NULL (meaning not used). We keep allocated empty strings to
    // allow behavior where prefixes exist but are empty.
    if(!remote_prefix){
        remote_prefix = nullptr; // treat as no prefix
    }
    if(!local_prefix){
        local_prefix = nullptr;
    }

    // Build minimal mosquitto context and bridge topic list to exercise bridge__remap_topic_in.
    struct mosquitto *context = (struct mosquitto*)calloc(1, sizeof(struct mosquitto));
    if(!context){
        free(initial_topic);
        free(remote_topic);
        if(remote_prefix) free(remote_prefix);
        if(local_prefix) free(local_prefix);
        return 0;
    }

    // Allocate bridge
    struct mosquitto__bridge *bridge = (struct mosquitto__bridge*)calloc(1, sizeof(struct mosquitto__bridge));
    if(!bridge){
        free(initial_topic);
        free(remote_topic);
        if(remote_prefix) free(remote_prefix);
        if(local_prefix) free(local_prefix);
        free(context);
        return 0;
    }
    bridge->topics = NULL;
    bridge->topic_remapping = true; // enable remapping behavior
    context->bridge = bridge;

    // Allocate a single bridge topic node and populate fields.
    struct mosquitto__bridge_topic *topic_node = (struct mosquitto__bridge_topic*)calloc(1, sizeof(struct mosquitto__bridge_topic));
    if(!topic_node){
        free(initial_topic);
        free(remote_topic);
        if(remote_prefix) free(remote_prefix);
        if(local_prefix) free(local_prefix);
        free(bridge);
        free(context);
        return 0;
    }

    // Set direction
    topic_node->direction = dir;

    // The function expects remote_topic to be set (it calls mosquitto_topic_matches_sub on it).
    // Copy remote_topic into the struct (use mosquitto_strdup if available, otherwise fallback to strdup)
#ifdef mosquitto_strdup
    topic_node->remote_topic = mosquitto_strdup(remote_topic ? remote_topic : "");
#else
    topic_node->remote_topic = remote_topic ? strdup(remote_topic) : strdup("");
#endif

    // remote_prefix/local_prefix: set to NULL if empty to emulate the "not set" state
    if(remote_prefix && strlen(remote_prefix) > 0){
#ifdef mosquitto_strdup
        topic_node->remote_prefix = mosquitto_strdup(remote_prefix);
#else
        topic_node->remote_prefix = strdup(remote_prefix);
#endif
    }else{
        topic_node->remote_prefix = NULL;
    }
    if(local_prefix && strlen(local_prefix) > 0){
#ifdef mosquitto_strdup
        topic_node->local_prefix = mosquitto_strdup(local_prefix);
#else
        topic_node->local_prefix = strdup(local_prefix);
#endif
    }else{
        topic_node->local_prefix = NULL;
    }

    // Link the single node into bridge->topics
    bridge->topics = topic_node;
    topic_node->next = NULL;

    // Prepare the topic pointer expected by bridge__remap_topic_in.
#ifdef mosquitto_strdup
    char *topic_for_call = mosquitto_strdup(initial_topic ? initial_topic : "");
#else
    char *topic_for_call = initial_topic ? strdup(initial_topic) : strdup("");
#endif

    // Call the target function.
    // It may free and replace *topic_for_call; that's expected.
    if(topic_for_call){
        bridge__remap_topic_in(context, &topic_for_call);
    }

    // Cleanup: free the potentially modified topic pointer and all allocated structures.
    if(topic_for_call){
        // Use mosquitto_FREE macro which sets ptr to NULL after freeing (declared in libcommon_memory.h).
#ifdef mosquitto_FREE
        mosquitto_FREE(topic_for_call);
#else
        free(topic_for_call);
        topic_for_call = nullptr;
#endif
    }

    // Free bridge topic node strings and node
    if(topic_node){
        if(topic_node->remote_topic){
#ifdef mosquitto_FREE
            mosquitto_FREE(topic_node->remote_topic);
#else
            free(topic_node->remote_topic);
#endif
        }
        if(topic_node->remote_prefix){
#ifdef mosquitto_FREE
            mosquitto_FREE(topic_node->remote_prefix);
#else
            free(topic_node->remote_prefix);
#endif
        }
        if(topic_node->local_prefix){
#ifdef mosquitto_FREE
            mosquitto_FREE(topic_node->local_prefix);
#else
            free(topic_node->local_prefix);
#endif
        }
        free(topic_node);
    }

    // Free bridge and context
    free(bridge);

    // Note: some mosquitto internals might have allocated resources; since we only used a minimal context,
    // free the top-level struct.
    free(context);

    // Free local temporary allocations that we created for partitioning (those not moved into topic_node)
    // initial_topic and remote_topic were either strdup'd into topic_for_call / topic_node->remote_topic earlier,
    // but we may have leftover allocations for remote_prefix/local_prefix when we set them to NULL.
    if(remote_topic){
        // remote_topic was used to initialize topic_node->remote_topic via strdup/mosquitto_strdup.
        free(remote_topic);
    }
    if(remote_prefix){
        free(remote_prefix);
    }
    if(local_prefix){
        free(local_prefix);
    }
    // initial_topic was strdup'ed to topic_for_call earlier; we freed topic_for_call via mosquitto_FREE or free,
    // but if we didn't use mosquitto_strdup for initial_topic then initial_topic still points to malloced buffer.
    if(initial_topic){
        free(initial_topic);
    }

    return 0;
}
