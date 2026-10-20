#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <random>
#include <mutex>

// Project headers (paths as seen in repository). If your build requires different
// include paths, change these to project-relative includes.
#ifdef __cplusplus
extern "C" {
#endif
#include "/src/mosquitto/lib/mosquitto_internal.h"
#include "/src/mosquitto/lib/net_mosq.h"
#ifdef __cplusplus
}
#endif

// Provide a simple deterministic mosquitto_getrandom implementation used by the code.
// The library declares mosquitto_getrandom as:
//   int mosquitto_getrandom(void *bytes, int count);
// so we must match that signature to avoid conflicting declarations.
extern "C" int mosquitto_getrandom(void *bytes, int count)
{
    if(!bytes || count <= 0) return 0;
    static std::mt19937_64 rng(0x9E3779B97F4A7C15ULL);
    static std::mutex rng_mutex;
    std::lock_guard<std::mutex> lock(rng_mutex);
    uint8_t *b = static_cast<uint8_t *>(bytes);
    int remaining = count;
    while(remaining >= static_cast<int>(sizeof(uint64_t))) {
        uint64_t v = rng();
        std::memcpy(b, &v, sizeof(v));
        b += sizeof(v);
        remaining -= static_cast<int>(sizeof(v));
    }
    if(remaining > 0) {
        uint64_t v = rng();
        std::memcpy(b, &v, remaining);
    }
    return count;
}

// Note: Do NOT provide fake/stub definitions for ws__prepare_packet or the fuzz helper
// functions here. The real implementations live in the project sources (e.g. net_ws.c
// and the fuzz helper compilation units). Defining stubs in this harness prevents the
// fuzzer from testing the real target functions.

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0) return 0;

    // Use first byte to configure websocket flags/opcode, rest is payload.
    uint8_t config_byte = Data[0];
    const uint8_t *payload_src = Data + 1;
    size_t payload_src_size = (Size > 1) ? (Size - 1) : 0;

    // Limit payload size to avoid huge allocations from malformed inputs.
    const size_t MAX_PAYLOAD = 64 * 1024; // 64 KiB
    size_t payload_len = std::min(payload_src_size, MAX_PAYLOAD);

    // Prepare a mosquitto object with zero-initialization.
    struct mosquitto *mosq = (struct mosquitto *)malloc(sizeof(struct mosquitto));
    if(!mosq) return 0;
    std::memset(mosq, 0, sizeof(struct mosquitto));

    // Initialize ws_data inside mosq. Only fields used by ws__prepare_packet are set.
    mosq->wsd.is_client = (config_byte & 0x1) ? true : false;
    // If config_byte is 0xFF, set opcode to UINT8_MAX to trigger the "use WS_BINARY" branch.
    mosq->wsd.opcode = config_byte;

    // Prepare a mosquitto__packet with flexible array payload[].
    // packet_length is expected to be WS_PACKET_OFFSET + actual_payload_length.
    // Allocate enough space for header bytes (WS_PACKET_OFFSET) + payload_len.
    size_t packet_payload_array_size = WS_PACKET_OFFSET + payload_len;
    // Add a small safety margin to avoid out-of-bounds writes by the function.
    const size_t SAFETY_MARGIN = 32;
    size_t alloc_size = sizeof(struct mosquitto__packet) + packet_payload_array_size + SAFETY_MARGIN;

    struct mosquitto__packet *packet = (struct mosquitto__packet *)malloc(alloc_size);
    if(!packet) {
        free(mosq);
        return 0;
    }
    // Zero everything to have deterministic baseline.
    std::memset(packet, 0, alloc_size);

    // Set packet metadata.
    packet->packet_length = (uint32_t)(WS_PACKET_OFFSET + payload_len);
    packet->pos = 0;
    packet->to_process = 0;
    packet->remaining_length = 0;
    packet->remaining_count = 0;

    // Copy fuzzer payload into the buffer area where ws__prepare_packet expects payload data.
    if(payload_len) {
        std::memcpy(&packet->payload[WS_PACKET_OFFSET], payload_src, payload_len);
    }

    // Call the real target function under test from the project (net_ws.c).
    ws__prepare_packet(mosq, packet);

    // Clean up.
    free(packet);
    free(mosq);

    return 0;
}