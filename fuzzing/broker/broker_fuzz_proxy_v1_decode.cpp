
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <string>
#include <unistd.h>

// Use the C header for stdint types (keeps compatibility)
#include <stdint.h>

// Include the project's internal mosquitto definitions (absolute path discovered in tree).
// Adjust if your checkout layout differs.
extern "C" {
#include "/src/mosquitto/lib/mosquitto_internal.h"
#include "/src/mosquitto/src/mosquitto_broker_internal.h"

// Provide weak stubs for functions that might be referenced by proxy_v1.c
// If the project provides them, those definitions will take precedence.

// Weak mosquitto_strdup fallback
__attribute__((weak)) char *mosquitto_strdup(const char *s)
{
    if(!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = (char*)malloc(n);
    if(!p) return NULL;
    memcpy(p, s, n);
    return p;
}

// Match project declaration for net__socket_get_address:
// int net__socket_get_address(mosq_sock_t sock, char *buf, size_t len, uint16_t *remote_port);
__attribute__((weak)) int net__socket_get_address(mosq_sock_t sock, char *address, size_t len, uint16_t *port)
{
    (void)sock;
    (void)address;
    (void)len;
    (void)port;
    // Indicate failure by returning -1 (replicating earlier harness behavior)
    return -1;
}

// ---- Workaround for void* -> uint8_t* assignments inside proxy_v1.c (C -> C++ conversion) ----
// proxy_v1.c was written in C and assigns the result of mosquitto_calloc (void*) directly to a uint8_t*.
// When compiling that C file as part of this C++ TU (by including it), C++ forbids implicit conversion from void*.
// To avoid editing project sources, provide a small wrapper macro so mosquitto_calloc(...) in proxy_v1.c
// becomes ((uint8_t*)mosquitto_calloc_impl(...)). Define the implementation function below.
//
// Note: The macro must be defined before including proxy_v1.c.
extern "C" void *mosquitto_calloc_impl(size_t nmemb, size_t size);
#define mosquitto_calloc(nmemb, size) ((uint8_t*)mosquitto_calloc_impl((nmemb), (size)))

extern "C" void *mosquitto_calloc_impl(size_t nmemb, size_t size)
{
    // Simple implementation using standard calloc.
    // This returns void*; the macro casts it to uint8_t* where needed.
    return calloc(nmemb, size);
}

// Redirect log__printf calls in proxy_v1.c to suppress log output during fuzzing.
// Must be defined after headers but before including proxy_v1.c.
#undef log__printf
#define log__printf(mosq, level, ...) (0)

// Include the real proxy_v1.c implementation from the project so the static
// function proxy_v1__decode is compiled into this TU. Adjust the path if needed.
#include "/src/mosquitto/src/proxy_v1.c"

} // extern "C"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data) return 0;

    // Ensure at least 2 bytes to avoid proxy_v1__decode writing at pos-1/pos-2
    size_t buf_size = (Size >= 2) ? Size : 2;
    uint8_t *buf = (uint8_t*)malloc(buf_size + 1);
    if(!buf) return 0;

    if(Size > 0){
        memcpy(buf, Data, Size);
    }
    buf[buf_size] = 0;

    // Construct a minimal mosquitto context using project struct definitions.
    struct mosquitto ctx;
    memset(&ctx, 0, sizeof(ctx));

    // Create a mock listener to avoid NULL pointer dereference in update_transport().
    // In the real broker, context->listener is always set when a connection is accepted.
    struct mosquitto__listener listener {};
    ctx.listener = &listener;

    // The project uses ctx.proxy.buf and ctx.proxy.pos
    ctx.proxy.buf = (uint8_t*)buf; // cast to uint8_t* to match struct type
    ctx.proxy.pos = buf_size;
    ctx.proxy.fam = 0;
    ctx.sock = (mosq_sock_t)-1;
    ctx.address = NULL;
    ctx.remote_port = 0;

    // Call the real target function from the project.
    (void)proxy_v1__decode(&ctx);

    // Cleanup
    if(ctx.address){
        free(ctx.address);
        ctx.address = NULL;
    }
    // proxy_cleanup is defined static in proxy_v1.c and is available in this TU,
    // so calling it will free ctx.proxy.buf etc as required.
    proxy_cleanup(&ctx);

    // Note: Do not free(buf) here because proxy_cleanup may have freed ctx.proxy.buf.
    // If it didn't, the allocator in proxy_cleanup likely uses the same heap and the
    // OS will reclaim at process exit during fuzzing harness teardown.

    return 0;
}
