#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <climits>

/* Mosquitto is C code. Ensure C linkage when included from C++ to avoid
 * name-mangling / undefined reference errors at link time.
 */
extern "C" {
#include "/src/mosquitto/lib/property_mosq.h"
#include "/src/mosquitto/lib/mosquitto_internal.h"
#include "/src/mosquitto/libcommon/property_common.h"
#include "/src/mosquitto/include/mosquitto/libcommon_properties.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0){
        return 0;
    }

    /* Prepare a mosquitto__packet_in populated with the fuzzer data.
     * property__read_all and the underlying packet__read_* helpers read from
     * packet->payload using packet->pos and packet->remaining_length.
     */
    struct mosquitto__packet_in packet;
    memset(&packet, 0, sizeof(packet));

    /* remaining_length is a uint32_t in the project. Cap Size appropriately. */
    uint32_t rlen = (Size > UINT32_MAX) ? UINT32_MAX : (uint32_t)Size;

    packet.payload = (uint8_t *)malloc((size_t)rlen);
    if(!packet.payload){
        return 0;
    }
    memcpy(packet.payload, Data, (size_t)rlen);
    packet.remaining_length = rlen;
    packet.pos = 0;

    mosquitto_property *properties = NULL;

    /* Use command value 0 for fuzzing; property__read_all will validate
     * properties against the command via mosquitto_property_check_all.
     */
    (void)property__read_all(0, &packet, &properties);

    /* Ensure any allocated properties are freed. property__read_all will free
     * on many error paths, but call this to be safe for successful or
     * partially-successful parses.
     */
    mosquitto_property_free_all(&properties);

    free(packet.payload);
    packet.payload = NULL;

    return 0;
}
