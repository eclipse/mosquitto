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
#include "quic.h"

#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

bool done_initialize = false;
const uint16_t UdpPort = 8883;
const uint64_t IdleTimeoutMs = 1000;
const uint32_t SendBufferLength = 100;
const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };
//const QUIC_REGISTRATION_CONFIG RegConfig = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

// #ifndef UNREFERENCED_PARAMETER
// #define UNREFERENCED_PARAMETER(P) (void)(P)
// #endif

// const QUIC_API_TABLE* MsQuic;
// const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };
// HQUIC Registration;
// HQUIC Configuration;
// // TODO: move to earlier
// bool done_initialize = false;

// // Should be defined in conf.c
// const uint16_t UdpPort = 8883;
// const uint64_t IdleTimeoutMs = 1000;
// const uint32_t SendBufferLength = 100;

// typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
//     QUIC_CREDENTIAL_CONFIG CredConfig;
//     union {
//         QUIC_CERTIFICATE_HASH CertHash;
//         QUIC_CERTIFICATE_HASH_STORE CertHashStore;
//         QUIC_CERTIFICATE_FILE CertFile;
//         QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
//     };
// } QUIC_CREDENTIAL_CONFIG_HELPER;

//
// Helper function to convert a hex character to its decimal value.
//
uint8_t
DecodeHexChar(
    _In_ char c
    )
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return 0;
}


//
// Helper function to convert a string of hex characters to a byte buffer.
//
uint32_t
DecodeHexBuffer(
    _In_z_ const char* HexBuffer,
    _In_ uint32_t OutBufferLen,
    _Out_writes_to_(OutBufferLen, return)
        uint8_t* OutBuffer
    )
{
    uint32_t HexBufferLen = (uint32_t)strlen(HexBuffer) / 2;
    if (HexBufferLen > OutBufferLen) {
        return 0;
    }

    for (uint32_t i = 0; i < HexBufferLen; i++) {
        OutBuffer[i] =
            (DecodeHexChar(HexBuffer[i * 2]) << 4) |
            DecodeHexChar(HexBuffer[i * 2 + 1]);
    }

    return HexBufferLen;
}


BOOLEAN
ServerLoadConfiguration(struct mosquitto__listener *listener)
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

    const char* Cert;
    const char* KeyFile;
    // if ((Cert = GetValue(argc, argv, "cert_hash")) != NULL) {
    //     //
    //     // Load the server's certificate from the default certificate store,
    //     // using the provided certificate hash.
    //     //
    //     uint32_t CertHashLen =
    //         DecodeHexBuffer(
    //             Cert,
    //             sizeof(Config.CertHash.ShaHash),
    //             Config.CertHash.ShaHash);
    //     if (CertHashLen != sizeof(Config.CertHash.ShaHash)) {
    //         return FALSE;
    //     }
    //     Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
    //     Config.CredConfig.CertificateHash = &Config.CertHash;

    // } else if ((Cert = GetValue(argc, argv, "cert_file")) != NULL &&
    //            (KeyFile = GetValue(argc, argv, "key_file")) != NULL) {
        //
        // Loads the server's certificate from the file.
        //
        // const char* Password = GetValue(argc, argv, "password");
        // if (Password != NULL) {
        //     Config.CertFileProtected.CertificateFile = (char*)Cert;
        //     Config.CertFileProtected.PrivateKeyFile = (char*)KeyFile;
        //     Config.CertFileProtected.PrivateKeyPassword = (char*)Password;
        //     Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
        //     Config.CredConfig.CertificateFileProtected = &Config.CertFileProtected;
        // } else {
            // Config.CertFile.CertificateFile = (char*)Cert;
            // Config.CertFile.PrivateKeyFile = (char*)KeyFile;
            //Config.CertFile.CertificateFile = (char*)Cert;
            Config.CertFile.CertificateFile = "/home/daiki/workspace/mosquitto/key_cert/server.cert";
            Config.CertFile.PrivateKeyFile = "/home/daiki/workspace/mosquitto/key_cert/server.key";
            Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
            Config.CredConfig.CertificateFile = &Config.CertFile;
        // }

    // } else {
    //     printf("Must specify ['-cert_hash'] or ['cert_file' and 'key_file' (and optionally 'password')]!\n");
    //     return FALSE;
    // }

    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &Configuration))) {
        fprintf(stderr, "ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    //
    // Loads the TLS credential part of the configuration.
    //
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &Config.CredConfig))) {
        fprintf(stderr, "ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}

//
// Allocates and sends some data over a QUIC stream.
//
void
ServerSend(
    _In_ HQUIC Stream
    )
{
    //
    // Allocates and builds the buffer to send over the stream.
    //
    void* SendBufferRaw = malloc(sizeof(QUIC_BUFFER) + SendBufferLength);
    if (SendBufferRaw == NULL) {
        printf("SendBuffer allocation failed!\n");
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        return;
    }
    QUIC_BUFFER* SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = (uint8_t*)SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = SendBufferLength;

    printf("[strm][%p] Sending data...\n", Stream);

    //
    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    //
    QUIC_STATUS Status;
    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        free(SendBufferRaw);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    }
}

//
// The server's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
ServerStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{

	//struct libmsquic_mqtt_data *ctx = (struct libmsquic_mqtt_data *)Context;
	//struct mosquitto *mosq = ctx->mosq;
    UNREFERENCED_PARAMETER(Context);
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
        for (int i = 0; i < Event->RECEIVE.BufferCount; i++) {
            printf("[strm][%p] (%d/%d): %d[%s]\n", Stream, i+1, Event->RECEIVE.BufferCount, Event->RECEIVE.Buffers[i].Length, (char*)Event->RECEIVE.Buffers[i].Buffer);
        }
        // TODO: mqtt cmd switch

        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer shut down\n", Stream);
        ServerSend(Stream);
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
ServerConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    fprintf(stderr, "ConnectionCallback\n");
    UNREFERENCED_PARAMETER(Context);
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
        //MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerStreamCallback, Context);
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerStreamCallback, NULL);
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
ServerListenerCallback(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    fprintf(stderr, "ListenerCallback");
    //struct libmsquic_mqtt* connection_context;
    UNREFERENCED_PARAMETER(Listener);
    UNREFERENCED_PARAMETER(Context);
    //struct libmsquic_mqtt_listener *context = (struct libmsquic_mqtt_listener*)Context;
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        //
        // A new connection is being attempted by a client. For the handshake to
        // proceed, the server must provide a configuration for QUIC to use. The
        // app MUST set the callback handler before returning.
        //
        //log__printf(NULL, MOSQ_LOG_WARNING, "Listener 1");
        // connection_context = mosquitto__calloc(1, sizeof(struct libmsquic_mqtt));
        // if(!connection_context){
        //     // TODO: stream cancelation?
        //     log__printf(NULL, MOSQ_LOG_WARNING, "CRITICAL: allocating stream_context failed");
        //     return;
        // }
        // connection_context->mosq = context__init(QUIC_CLIENT);
        //MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, connection_context);
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, NULL);
        //Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, context->listener->Configuration);
        Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
        //printf("QUIC_LISTENER_EVENT_NEW_CONNECTION done\n");
        break;
    default:
        break;
    }
    return Status;
}


bool RunServer(struct mosquitto__listener *listener)
{
    QUIC_STATUS Status;
    HQUIC Listener = NULL;
    // struct libmsquic_mqtt_listener *context = mosquitto__calloc(1, sizeof(struct libmsquic_mqtt_listener));
    // if(!context){
    //     return;
    // }
    // context->listener = listener;

    // TODO: should be passed by argument
    QUIC_ADDR Address = {0};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&Address, UdpPort);

    //
    // Load the server configuration based on the command line.
    //
    //if (!ServerLoadConfiguration(argc, argv)) {
    if (!ServerLoadConfiguration(listener)) {
        fprintf(stderr, "failed to do ServerLoadConfiguration\n");
        return 1;
    }

    //
    // Create/allocate a new listener object.
    //
    //if (QUIC_FAILED(Status = MsQuic->ListenerOpen(Registration, ServerListenerCallback, context, &Listener))) {
        fprintf(stderr, "Doing ListenerOpen\n");
    if (QUIC_FAILED(Status = MsQuic->ListenerOpen(Registration, ServerListenerCallback, NULL, &Listener))) {
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

bool mosq_quic_init(struct mosquitto__listener *listener, const struct mosquitto__config *conf)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (!done_initialize){
        if (QUIC_FAILED(Status = MsQuicOpen(&MsQuic))) {
            printf("MsQuicOpen failed, 0x%x!\n", Status);
            return 1;
        }

        const QUIC_REGISTRATION_CONFIG RegConfig = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
        //HQUIC Registration;

        if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
            printf("RegistrationOpen failed, 0x%x!\n", Status);
            return 1;
        }
        if(RunServer(listener)) {
            return 1;
        }
        log__printf(NULL, MOSQ_LOG_WARNING, "Start server on port %d", UdpPort);
    }
    done_initialize = true;
    return 0;
}


// // TODO: unify with lib
// static int net__init_quic(const struct mosquitto__config *conf){
//     // TODO: load config from conf.
//     QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
//     //
//     // Open a handle to the library and get the API function table.
//     //
//     if (QUIC_FAILED(Status = MsQuicOpen(&MsQuic))) {
//         printf("MsQuicOpen failed, 0x%x!\n", Status);
//         return Status;
//     }

//     //
//     // Create a registration for the app's connections.
//     //
// 	const QUIC_REGISTRATION_CONFIG RegConfig = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
//     if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
//         printf("RegistrationOpen failed, 0x%x!\n", Status);
//         return Status;
//     }

// 	return 0;
// }

// bool mosq_quic_init(struct mosquitto__listener *listener, const struct mosquitto__config *conf)
// {
//     QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
//     if (!done_initialize) {
//         if(QUIC_FAILED(Status = net__init_quic(conf))) {
//             return Status;
//         }

//         //INFO: run once?
//         if(RunServer(listener)) {
//             log__printf(NULL, MOSQ_LOG_WARNING, "Start server on port %d", UdpPort);
//         }
//     }
//     done_initialize = true;
//     return 0;
// }


#endif
