#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <cstdlib>
#include <algorithm>

// Ensure C linkage for the mosquitto C headers so the C symbols are not C++-mangled.
extern "C" {
#include "/src/mosquitto/include/mosquitto.h"
#include "/src/mosquitto/lib/mosquitto_internal.h"
#include "/src/mosquitto/lib/will_mosq.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    // Basic guard.
    if(!Data || Size == 0) return 0;

    // Create a zeroed mosquitto structure so will__set has a valid object to operate on.
    struct mosquitto *mosq = (struct mosquitto *)calloc(1, sizeof(struct mosquitto));
    if(!mosq) return 0;
    // Make protocol MQTT v5 by default (some paths require this).
    mosq->protocol = mosq_p_mqtt5;
    mosq->will = NULL;

    size_t pos = 0;

    // Extract a topic length (bounded) from the first byte.
    size_t topic_len = 0;
    if(pos < Size){
        topic_len = Data[pos++];
        // bound topic length to reasonable value to avoid excessive allocations
        topic_len = std::min<size_t>(topic_len, 1024);
    }

    // Build a topic string from the next topic_len bytes (or remaining bytes).
    size_t avail = (pos < Size) ? (Size - pos) : 0;
    size_t copy_len = std::min(topic_len, avail);
    std::string topic;
    if(copy_len > 0){
        topic.assign(reinterpret_cast<const char*>(Data + pos), copy_len);
        pos += copy_len;
    }else{
        // Ensure topic is at least an empty string (not a null pointer).
        topic = "";
    }
    // Guarantee null-termination for C APIs.
    // topic.c_str() is guaranteed null-terminated by std::string.

    // Extract payload length from next byte if available. Keep it small and within remaining buffer.
    int payloadlen = 0;
    if(pos < Size){
        payloadlen = static_cast<int>(Data[pos++]);
        // Allow payloadlen to be up to remaining bytes but keep it reasonable.
        if(payloadlen < 0) payloadlen = 0;
        size_t remaining = (pos < Size) ? (Size - pos) : 0;
        if((size_t)payloadlen > remaining){
            payloadlen = static_cast<int>(remaining);
        }
    }else{
        payloadlen = 0;
    }

    // Determine payload pointer and advance pos over payload bytes.
    const void *payload = nullptr;
    if(payloadlen > 0){
        size_t remaining = (pos < Size) ? (Size - pos) : 0;
        size_t use_len = std::min<size_t>((size_t)payloadlen, remaining);
        if(use_len > 0){
            payload = Data + pos;
            pos += use_len;
            // payloadlen was already clamped above to remaining, so use_len should equal payloadlen
        }else{
            payload = nullptr;
            // ensure payloadlen is set to 0 if there's no data
            payloadlen = 0;
        }
    }

    // Extract qos (0..2) from next byte if present.
    int qos = 0;
    if(pos < Size){
        qos = Data[pos++] % 3; // valid qos values 0,1,2
    }

    // Extract retain flag from next byte if present.
    bool retain = false;
    if(pos < Size){
        retain = (Data[pos++] & 0x1) != 0;
    }

    // We will not construct properties for simplicity. Pass nullptr to skip MQTT5 property checks.
    mosquitto_property *properties = nullptr;

    // Call the function under test.
    // The function will copy topic and payload internally, or return an error.
    (void)will__set(mosq, topic.c_str(), payloadlen, payload, qos, retain, properties);

    // Clean up any will structure allocated by will__set.
    will__clear(mosq);

    // Free the mosquitto object.
    free(mosq);

    return 0;
}
