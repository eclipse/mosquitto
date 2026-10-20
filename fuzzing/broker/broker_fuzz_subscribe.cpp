// Fixed fuzzer harness for int handle__subscribe(struct mosquitto *context).
// Main fixes:
//  - Initialize subscription subsystem if not already initialized (sub__init).
//  - Call sub__clean_session(context) after handle__subscribe to remove any
//    subscriptions associated with the test context so the global subscription
//    trees don't retain pointers to freed contexts (prevents UAF across fuzz iterations).
//  - Call packet__cleanup_all_no_locks(context) to free any outgoing packets
//    queued by the handler so we don't leak memory allocated by packet__alloc/send__suback.
// This file assumes it's built in the project environment with the mosquitto
// headers and sources available at the absolute paths used below.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

extern "C" {
  /* Include project headers declaring struct mosquitto, db and handle__subscribe. */
  #include "/src/mosquitto/lib/mosquitto_internal.h"
  #include "/src/mosquitto/src/mosquitto_broker_internal.h"

  /* Fallback declaration in case include paths differ. The includes above should
   * provide this, but keep this as a safety net.
   */
  int handle__subscribe(struct mosquitto *context);

  /* sub__init and sub__clean_session are declared in mosquitto_broker_internal.h,
   * but redeclare here to be explicit in case of include path issues.
   */
  int sub__init(void);
  int sub__clean_session(struct mosquitto *context);

  /* Ensure packet cleanup no-locks is available (declared in lib/packet_mosq.h).
   * We call the no-lock variant because the harness-created context has zeroed
   * mutexes and calling the locked variant would be unsafe.
   */
  void packet__cleanup_all_no_locks(struct mosquitto *mosq);
}

/* LLVM fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size < 2){
        return 0;
    }

    /* Allocate and zero a mosquitto context. */
    struct mosquitto *context = (struct mosquitto *)calloc(1, sizeof(struct mosquitto));
    if(!context) return 0;

    /* Set required fields to trigger subscribe handling code path. */
    context->state = mosq_cs_active;
    /* Use MQTT 3.1.1 to avoid MQTT5 property parsing paths. */
    context->protocol = mosq_p_mqtt311;
    context->max_qos = 2;
    context->retain_available = 1;
    context->is_bridge = false;

    /* Provide small non-NULL id/address to avoid potential null derefs in logging
     * and to satisfy mosquitto_acl_check's early checks.
     */
    context->id = strdup("fuzz-client");
    context->address = strdup("127.0.0.1");

    /* Ensure the global db.config is allocated. mosquitto_acl_check() accesses
     * db.config and will dereference it; when running the harness in isolation
     * this may otherwise be NULL and lead to a crash (seen as ASan SEGV).
     *
     * We allocate and zero a struct mosquitto__config so plugin pointers are NULL
     * and per_listener_settings is false by default.
     */
    bool db_config_alloc = false;
    if(db.config == NULL){
        db.config = (struct mosquitto__config *)calloc(1, sizeof(struct mosquitto__config));
        if(db.config){
            db_config_alloc = true;
            /* Default to no per-listener plugins to avoid listener dereferences. */
            db.config->per_listener_settings = false;
        }
    }

    /* Ensure subscription subsystem is initialized so normal_subs/shared_subs
     * roots exist and are in a consistent state.
     */
    if(db.normal_subs == NULL && db.shared_subs == NULL){
        (void)sub__init();
    }

    /* Prepare the incoming packet structure to point at the fuzzer data. */
    struct mosquitto__packet_in *pin = &context->in_packet;

    pin->payload = (uint8_t *)malloc(Size);
    if(!pin->payload){
        if(context->id) { free(context->id); context->id = NULL; }
        if(context->address) { free(context->address); context->address = NULL; }
        free(context);
        if(db_config_alloc){
            free(db.config);
            db.config = NULL;
        }
        return 0;
    }
    memcpy(pin->payload, Data, Size);

    /* Set packet metadata expected by packet__read_* helpers. */
    pin->remaining_length = (uint32_t)Size;
    pin->packet_length = (uint32_t)Size;
    pin->pos = 0;
    pin->remaining_mult = 0;
    pin->remaining_count = 0;
    pin->to_process = 0;
    pin->packet_buffer = NULL;
    pin->packet_buffer_pos = 0;
    pin->packet_buffer_size = 0;

    /* The handler checks that command == (CMD_SUBSCRIBE|2). */
    pin->command = (uint8_t)(CMD_SUBSCRIBE | 2);

    /* Call the target function under test. */
    (void)handle__subscribe(context);

    /* After handling subscribe, remove any subscriptions attached to this context
     * so the global subscription lists do not retain pointers to our context when
     * we free it. This prevents heap-use-after-free across fuzz iterations.
     */
    (void)sub__clean_session(context);

    /* Free any outgoing packets queued by the handler so we don't leak memory
     * allocated by packet__alloc/send__suback. We use the no-locks variant so
     * we don't attempt to lock uninitialized mutexes in our zeroed context.
     *
     * Note: packet__cleanup_all_no_locks will call packet__cleanup(&context->in_packet),
     * which may free in_packet.payload. To avoid double-freeing later, clear the
     * pointer after calling this cleanup.
     */
    packet__cleanup_all_no_locks(context);
    context->in_packet.payload = NULL;

    /* Clean up allocated memory. */
    if(pin->payload){
        free(pin->payload);
        pin->payload = NULL;
    }
    if(context->id){
        free(context->id);
        context->id = NULL;
    }
    if(context->address){
        free(context->address);
        context->address = NULL;
    }

    free(context);

    /* Free the db.config we allocated for the harness, if any. Leave db in a
     * clean state for subsequent fuzz iterations.
     */
    if(db_config_alloc && db.config){
        free(db.config);
        db.config = NULL;
    }

    return 0;
}
