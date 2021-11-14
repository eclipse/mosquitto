#ifdef WITH_QUIC

#include "config.h"

#include </usr/local/msquic/include/msquic.h>
#include </usr/local/msquic/include/msquic_posix.h>
#include "mosquitto_internal.h"
#include "mosquitto_broker_internal.h"
#include "mqtt_protocol.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "sys_tree.h"
#include "util_mosq.h"
#include "../lib/quic/common.h"

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

    // TODO: use "if(listener->certfile && listener->keyfile)"
    fprintf(stderr, "certfile: %s\n", listener->certfile);
    fprintf(stderr, "keyfile: %s\n", listener->keyfile);

    Config.CertFile.CertificateFile = listener->certfile;
    Config.CertFile.PrivateKeyFile = listener->keyfile;
    // Config.CertFile.CertificateFile = "/home/daiki/workspace/mosquitto/key_cert/server.cert";
    // Config.CertFile.PrivateKeyFile = "/home/daiki/workspace/mosquitto/key_cert/server.key";
    Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    Config.CredConfig.CertificateFile = &Config.CertFile;

    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(listener->Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &listener->Configuration))) {
        fprintf(stderr, "ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    //
    // Loads the TLS credential part of the configuration.
    //
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(listener->Configuration, &Config.CredConfig))) {
        fprintf(stderr, "ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}

// The server's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
stream_callback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{

	struct libmsquic_mqtt *connection_context = (struct libmsquic_mqtt *)Context;
	struct mosquitto *mosq = connection_context->mosq;
    int rc;
    uint8_t *buf;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        free(Event->SEND_COMPLETE.ClientContext);
        printf("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream.
        //
        printf("[strm][%p] Data received\n", Stream);
        sleep(1);
        static int switch_flag = 0;
        for (int i = 0; i < Event->RECEIVE.BufferCount; i++) {
			int len =Event->RECEIVE.Buffers[i].Length;
            printf("[strm][%p] (%d/%d): %d[%s]\n", Stream, i+1, Event->RECEIVE.BufferCount, len, (char*)Event->RECEIVE.Buffers[i].Buffer);
            buf = (uint8_t*)Event->RECEIVE.Buffers[i].Buffer;
            fprintf(stderr, "len=%d [", len);
            for (int j = 0; j < len; j++) {
                fprintf(stderr, "%d, ", buf[j]);
            }
			static int switch_flag = 0;
			fprintf(stderr, "] before\n");
            if (Event->RECEIVE.Buffers[i].Length == 4 && switch_flag == 0) {
                //buf = malloc(sizeof(uint8_t) * 4);
                buf[0] = 98; // PUBREL
                buf[1] = 2;
                buf[2] = 0;
                buf[3] = 1;
                switch_flag++;
            }
            fprintf(stderr, "len=%d [", len);
            for (int j = 0; j < len; j++) {
                fprintf(stderr, "%d, ", buf[j]);
            }
			fprintf(stderr, "] after\n");
            stream_packet__read2(mosq, buf, len);
        }
        fprintf(stderr, "[strm] handle command end\n");
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer shut down\n", Stream);
        sleep(1);
        //ServerSend(Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", Stream);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        printf("[strm][%p] All done\n", Stream);
        MsQuic->StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// The server's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
connection_callback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    struct libmsquic_mqtt *connection_context;
    fprintf(stderr, "ConnectionCallback\n");
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        printf("[conn][%p] Connected\n", Connection);
        MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            printf("[conn][%p] Successfully shut down on idle.\n", Connection);
        } else {
            printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        printf("[conn][%p] All done\n", Connection);
        MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        //
        // The peer has started/created a new stream. The app MUST set the
        // callback handler before returning.
        //
        printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
        struct libmsquic_mqtt *connection_context = (struct libmsquic_mqtt*)Context;
        connection_context->mosq->Connection = Connection;
        connection_context->mosq->Stream = Event->PEER_STREAM_STARTED.Stream;
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)stream_callback, connection_context);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        //
        // The connection succeeded in doing a TLS resumption of a previous
        // connection's session.
        //
        printf("[conn][%p] Connection resumed!\n", Connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
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
    fprintf(stderr, "ListenerCallback");
    struct libmsquic_mqtt* connection_context;
    UNREFERENCED_PARAMETER(Listener);
    struct libmsquic_mqtt_listener *listener_context = (struct libmsquic_mqtt_listener*)Context;
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        //
        // A new connection is being attempted by a client. For the handshake to
        // proceed, the server must provide a configuration for QUIC to use. The
        // app MUST set the callback handler before returning.
        //
        connection_context = mosquitto__calloc(1, sizeof(struct libmsquic_mqtt));
        if(!connection_context){
            // TODO: stream cancelation?
            log__printf(NULL, MOSQ_LOG_WARNING, "CRITICAL: allocating stream_context failed");
            return;
        }
        connection_context->mosq = context__init(QUIC_CLIENT);
        connection_context->mosq->listener = listener_context->listener;
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)connection_callback, connection_context);
        Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, listener_context->listener->Configuration);
        break;
    default:
        break;
    }
    return Status;
}


bool run_server(struct mosquitto__listener *listener)
{
    QUIC_STATUS Status;
    HQUIC Listener = NULL;
    struct libmsquic_mqtt_listener *context = mosquitto__calloc(1, sizeof(struct libmsquic_mqtt_listener));
    if(!context){
        return;
    }
    context->listener = listener;

    // TODO: should be passed by argument
    QUIC_ADDR Address = {0};
    QUIC_ADDR_STR AddrStr = {0};
    QuicAddrFromString(listener->host, listener->port, &Address);
    QuicAddrToString(&Address, &AddrStr);
    fprintf(stderr, "trying to listen on address:[%s]\n", AddrStr.Address);

    //
    // Load the server configuration based on the command line.
    //
    if (!load_configuration(listener)) {
        fprintf(stderr, "failed to do ServerLoadConfiguration\n");
        return 1;
    }

    //
    // Create/allocate a new listener object.
    //
    fprintf(stderr, "Doing ListenerOpen\n");
    if (QUIC_FAILED(Status = MsQuic->ListenerOpen(listener->Registration, listener_callback, context, &Listener))) {
        fprintf(stderr, "ListenerOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    //
    // Starts listening for incoming connections.
    //
    if (QUIC_FAILED(Status = MsQuic->ListenerStart(Listener, &Alpn, 1, &Address))) {
        fprintf(stderr, "ListenerStart failed, 0x%x!\n", Status);
        goto Error;
    }
    return 0;

Error:

    if (Listener != NULL) {
        MsQuic->ListenerClose(Listener);
    }
    return 1;
}

bool mosq_quic_listen(struct mosquitto__listener *listener, const struct mosquitto__config *conf)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (!MsQuic) {
        if(QUIC_FAILED(Status = quic_init(&listener->Registration, conf))) {
            return Status;
        }
    }

    if(run_server(listener)) {
        log__printf(NULL, MOSQ_LOG_WARNING, "Start server on port %d", listener->port);
    }

    return 0;
}

#endif
