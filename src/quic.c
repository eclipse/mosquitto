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
        mosq->transport = mosq_t_quic;
        mosq->listener->client_count++;
        // TODO: ipv6
        struct sockaddr_in *sin = (struct sockaddr_in*)Event->NEW_CONNECTION.Info->RemoteAddress;
        mosq->address = (char*)mosquitto__malloc(INET_ADDRSTRLEN);
        if(!mosq->address){
            break;
        }
        inet_ntop(AF_INET, &sin->sin_addr, mosq->address, INET_ADDRSTRLEN);
        mosq->remote_port = htons(sin->sin_port);

        if((mosq->listener->max_connections > 0 && mosq->listener->client_count > mosq->listener->max_connections)
                || (db.config->global_max_connections > 0 && HASH_CNT(hh_sock, db.contexts_by_sock) > (unsigned int)db.config->global_max_connections)){
            if(db.config->connection_messages == true){
                log__printf(NULL, MOSQ_LOG_NOTICE, "Client connection from %s denied: max_connections exceeded.", mosq->address);
            }
            mosquitto__free(mosq->address);
            mosquitto__free(mosq);
            mosq = NULL;
            break;
        }

        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)connection_callback, mosq);
        Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, listener_context->Configuration);
        break;
    default:
        break;
    }
    return Status;
}


QUIC_STATUS run_server(struct mosquitto__listener *listener)
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
    QUIC_CREDENTIAL_CONFIG_HELPER Config;
    memset(&Config, 0, sizeof(Config));
    Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;
    Config.CertFile.CertificateFile = listener->certfile;
    Config.CertFile.PrivateKeyFile = listener->keyfile;
    Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    Config.CredConfig.CertificateFile = &Config.CertFile;
    if (QUIC_FAILED(Status = load_configuration(&listener->Configuration, &listener->Registration, &Config.CredConfig))){
        log__printf(NULL, MOSQ_LOG_ERR, "Error: load_configuration failed 0x%x!", Status);
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
    return Status;

Error:

    if (listener->Listener != NULL) {
        MsQuic->ListenerClose(listener->Listener);
    }
    return Status;
}

bool mosq_quic_listen(struct mosquitto__listener *listener)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (!MsQuic) {
        if(QUIC_FAILED(Status = quic_init(&listener->Registration))){
            log__printf(NULL, MOSQ_LOG_ERR, "Error: quic_init_failed 0x%x!", Status);
            return 1;
        }
    }

    if(QUIC_FAILED(Status = run_server(listener))){
        log__printf(NULL, MOSQ_LOG_ERR, "Error: run_server failed 0x%x!", Status);
        return 1;
    }
    log__printf(NULL, MOSQ_LOG_QUIC, "Start server on port %d", listener->port);

    return 0;
}

void mosq_quic_listener_stop(struct mosquitto__listener *listener)
{
    MsQuic->ListenerClose(listener->Listener);
}

#endif
