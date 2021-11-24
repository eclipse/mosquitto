#ifdef WITH_QUIC

#include "config.h"
#include <msquic.h>
#include <msquic_posix.h>
#include "quic/common.h"
#include "memory_mosq.h"

//
// Helper function to load a client configuration.
//
BOOLEAN
client_load_configuration(
    BOOLEAN Unsecure,
	struct mosquitto* mosq
    )
{
    QUIC_SETTINGS Settings_ = {0};
    //
    // Configures the client's idle timeout.
    //
    Settings_.IdleTimeoutMs = 10000;
    Settings_.IsSet.IdleTimeoutMs = TRUE;

    //
    // Configures a default client configuration, optionally disabling
    // server certificate validation.
    //
    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    if (Unsecure) {
        CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(mosq->Registration, &Alpn, 1, &Settings_, sizeof(Settings_), NULL, &mosq->Configuration))) {
        log__printf(mosq, MOSQ_LOG_ERR, "Error: ConfigurationOpen failed, 0x%x!", Status);
        return FALSE;
    }

    //
    // Loads the TLS credential part of the configuration. This is required even
    // on client side, to indicate if a certificate is required or not.
    //
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(mosq->Configuration, &CredConfig))) {
        log__printf(mosq, MOSQ_LOG_ERR, "Error: ConfigurationLoadCredential failed, 0x%x!", Status);
        return FALSE;
    }

    return TRUE;
}

//
// Runs the client side of the protocol.
//
int
quic_connect(const char *host, uint16_t port, struct mosquitto *mosq)
{
    //
    // Load the client configuration based on the "unsecure" command line option.
    // TODO: change to secure flag
    if (!client_load_configuration(1, mosq)) {
		log__printf(mosq, MOSQ_LOG_ERR, "Error: client_load_configuration failed");
        return 1;
    }

    QUIC_STATUS Status;
    const char* ResumptionTicketString = NULL;

    //
    // Allocate a new connection object.
    //
    if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(mosq->Registration, connection_callback, mosq, &mosq->Connection))) {
        log__printf(mosq, MOSQ_LOG_ERR, "Error: ConnectionOpen failed, 0x%x!", Status);
        goto Error;
    }

    // if ((ResumptionTicketString = GetValue(argc, argv, "ticket")) != NULL) {
    //     //
    //     // If provided at the command line, set the resumption ticket that can
    //     // be used to resume a previous session.
    //     //
    //     uint8_t ResumptionTicket[1024];
    //     uint16_t TicketLength = (uint16_t)DecodeHexBuffer(ResumptionTicketString, sizeof(ResumptionTicket), ResumptionTicket);
    //     if (QUIC_FAILED(Status = MsQuic->SetParam(Connection, QUIC_PARAM_LEVEL_CONNECTION, QUIC_PARAM_CONN_RESUMPTION_TICKET, TicketLength, ResumptionTicket))) {
    //         printf("SetParam(QUIC_PARAM_CONN_RESUMPTION_TICKET) failed, 0x%x!\n", Status);
    //         goto Error;
    //     }
    // }

    log__printf(mosq, MOSQ_LOG_QUIC, "[conn][%p] Connecting...", mosq->Connection);

    //
    // Start the connection to the server.
    //
    if (QUIC_FAILED(Status = MsQuic->ConnectionStart(mosq->Connection, mosq->Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, host, port))) {
        log__printf(mosq, MOSQ_LOG_ERR, "Error: ConnectionStart failed, 0x%x!\n", Status);
        goto Error;
    }

    return 0;

Error:

    if (QUIC_FAILED(Status) && mosq->Connection != NULL) {
        MsQuic->ConnectionClose(mosq->Connection);
    }
    return 1;
}


void quic_cleanup()
{
    if(MsQuic){
        MsQuicClose(MsQuic);
        MsQuic = NULL;
    }
}

int quic_close_internal(HQUIC *Registration, HQUIC *Configuration, HQUIC *Connection, HQUIC *Stream)
{
    sleep(1);
    if (*Stream) {
        MsQuic->StreamShutdown(*Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        *Stream = NULL;
    }

    if (*Connection) {
        MsQuic->ConnectionShutdown(*Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        *Connection = NULL;
    }

    if (*Configuration) {
        MsQuic->ConfigurationClose(*Configuration);
        *Configuration = NULL;
    }

    if (*Registration) {
        MsQuic->RegistrationClose(*Registration);
        *Registration = NULL;
    }
    return 0;
}

int quic_disconnect(struct mosquitto *mosq)
{
    return quic_close_internal(&mosq->Registration, &mosq->Configuration, &mosq->Connection, &mosq->Stream);
}

#endif