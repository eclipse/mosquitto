#ifndef QUIC_COMMON_H
#define QUIC_COMMON_H

#include "config.h"
#include "../mosquitto_internal.h"
#include <msquic.h>
#include <msquic_posix.h>
#include <stddef.h>

const QUIC_API_TABLE* MsQuic;
const QUIC_BUFFER Alpn;

struct libmsquic_mqtt_listener {
	struct mosquitto__listener *listener;
};

struct libmsquic_mqtt {
	struct mosquitto *mosq;
};

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif
typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    union {
        QUIC_CERTIFICATE_HASH CertHash;
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        QUIC_CERTIFICATE_FILE CertFile;
        QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
    };
} QUIC_CREDENTIAL_CONFIG_HELPER;

int init_quic(HQUIC *Registration, const struct mosquitto__config *conf);
int quic_send(struct mosquitto *mosq, const void *buf, size_t count);
// TODO remove
//int stream_packet__read(struct mosquitto *mosq, uint8_t* buf, size_t len);
QUIC_STATUS
QUIC_API
stream_callback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    );
QUIC_STATUS
QUIC_API
connection_callback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    );

#endif // QUIC_COMMON_H