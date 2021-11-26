#ifdef WITH_QUIC

#include "config.h"

#include <msquic.h>
#include <msquic_posix.h>
#include "mosquitto_internal.h"
#include "mosquitto_broker_internal.h"
#include "mqtt_protocol.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "sys_tree.h"
#include "util_mosq.h"

#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>


bool done_initialize = false;
const uint16_t UdpPort = 8883;
const uint64_t IdleTimeoutMs = 10000;
const uint32_t SendBufferLength = 100;

BOOLEAN
load_configuration(struct mosquitto__listener *listener)
{
    QUIC_SETTINGS Settings = {0};
    //
    // Configures the server's idle timeout.
    //
    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    //
    // Configures the server's resumption level to allow for resumption and
    // 0-RTT.
    //
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;
    //
    // Configures the server's settings to allow for the peer to open a single
    // bidirectional stream. By default connections are not configured to allow
    // any streams from the peer.
    //
    Settings.PeerBidiStreamCount = 1;
    Settings.IsSet.PeerBidiStreamCount = TRUE;

    QUIC_CREDENTIAL_CONFIG_HELPER Config;
    memset(&Config, 0, sizeof(Config));
    Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;


    Config.CertFile.CertificateFile = listener->certfile;
    Config.CertFile.PrivateKeyFile = listener->keyfile;
    Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    Config.CredConfig.CertificateFile = &Config.CertFile;

    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(listener->Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &listener->Configuration))) {
        log__printf(NULL, MOSQ_LOG_ERR, "Error: ConfigurationOpen failed, 0x%x!", Status);
        return FALSE;
    }

    //
    // Loads the TLS credential part of the configuration.
    //
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(listener->Configuration, &Config.CredConfig))) {
        log__printf(NULL, MOSQ_LOG_ERR, "Error: ConfigurationLoadCredential failed, 0x%x!", Status);
        return FALSE;
    }

    return TRUE;
}

//
// The server's callback for listener events from MsQuic.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
listener_callback(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    struct mosquitto *mosq;
    UNREFERENCED_PARAMETER(Listener);
    struct mosquitto__listener *listener_context = (struct mosquitto__listener*)Context;
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        //
        // A new connection is being attempted by a client. For the handshake to
        // proceed, the server must provide a configuration for QUIC to use. The
        // app MUST set the callback handler before returning.
        //
        mosq = context__init();
        mosq->listener = listener_context;
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)connection_callback, mosq);
        Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, listener_context->Configuration);
        break;
    default:
        break;
    }
    return Status;
}


bool run_server(struct mosquitto__listener *listener)
{
    QUIC_STATUS Status;
    // TODO: should be passed by argument
    QUIC_ADDR Address = {0};
    QUIC_ADDR_STR AddrStr = {0};
    if (!listener->host){
        listener->host = "0.0.0.0";
    }
    QuicAddrFromString(listener->host, listener->port, &Address);
    QuicAddrToString(&Address, &AddrStr);

    //
    // Load the server configuration based on the command line.
    //
    if (!load_configuration(listener)) {
        log__printf(NULL, MOSQ_LOG_ERR, "Error: load_configuration failed");
        return 1;
    }

    //
    // Create/allocate a new listener object.
    //
    if (QUIC_FAILED(Status = MsQuic->ListenerOpen(listener->Registration, listener_callback, listener, &listener->Listener))) {
        log__printf(NULL, MOSQ_LOG_ERR, "Error: ListenerOpen failed, 0x%x!", Status);
        goto Error;
    }

    //
    // Starts listening for incoming connections.
    //
    if (QUIC_FAILED(Status = MsQuic->ListenerStart(listener->Listener, &Alpn, 1, &Address))) {
        log__printf(NULL, MOSQ_LOG_ERR, "Error: ListenerStart failed, 0x%x!", Status);
        goto Error;
    }
    return 0;

Error:

    if (listener->Listener != NULL) {
        MsQuic->ListenerClose(listener->Listener);
    }
    return 1;
}

bool mosq_quic_listen(struct mosquitto__listener *listener)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (!MsQuic) {
        if(QUIC_FAILED(Status = quic_init(&listener->Registration))) {
            log__printf(NULL, MOSQ_LOG_ERR, "Error: quic_init_failed");
            return Status;
        }
    }

    if(run_server(listener)) {
        log__printf(NULL, MOSQ_LOG_ERR, "Error: run_server failed");
    }
    log__printf(NULL, MOSQ_LOG_QUIC, "Start server on port %d", listener->port);

    return 0;
}

void mosq_quic_listener_stop(struct mosquitto__listener *listener)
{
    MsQuic->ListenerClose(listener->Listener);
}

#endif
