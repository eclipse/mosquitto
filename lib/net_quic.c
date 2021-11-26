
#include "config.h"

#ifdef WITH_QUIC

#include <msquic.h>
#include <msquic_posix.h>
#include "logging_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#include "mqtt_protocol.h"
// To avoid segv on server
#include "memory_mosq.h"

#ifdef WITH_BROKER
#  include "sys_tree.h"
#  include "mosquitto_broker_internal.h"
#  include "send_mosq.h"
#endif

const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
stream_callback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    );

QUIC_STATUS quic_init(HQUIC *Registration)
{
    // TODO: load config from conf.
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    //
    // Open a handle to the library and get the API function table.
    //
    if (QUIC_FAILED(Status = MsQuicOpen(&MsQuic))) {
        log__printf(NULL, MOSQ_LOG_ERR, "Error: MsQuicOpen failed, 0x%x!", Status);
        return Status;
    }

    //
    // Create a registration for the app's connections.
    //
	const QUIC_REGISTRATION_CONFIG RegConfig = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, Registration))) {
        log__printf(NULL, MOSQ_LOG_ERR, "Error: RegistrationOpen failed, 0x%x!", Status);
        return Status;
    }

	return Status;
}


ssize_t quic_send(struct mosquitto *mosq, const void *buf, size_t count)
{

    QUIC_STATUS Status;
    uint8_t* SendBufferRaw;
    QUIC_BUFFER* SendBuffer;

    // WARN: when is this freed?
    SendBufferRaw = (uint8_t*)mosquitto__malloc(sizeof(QUIC_BUFFER) + count);
    if (SendBufferRaw == NULL) {
        // TODO: log warning
        log__printf(mosq, MOSQ_LOG_ERR, "Error: SendBuffer allocation failed!");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = (uint16_t)count;
    memcpy(SendBuffer->Buffer, buf, count);

    if (!mosq->Stream) {
		//
		// Create/allocate a new bidirectional stream. The stream is just allocated
		// and no QUIC stream identifier is assigned until it's started.
		//
        if (QUIC_FAILED(Status = MsQuic->StreamOpen(mosq->Connection, QUIC_STREAM_OPEN_FLAG_NONE, stream_callback, mosq, &mosq->Stream))) {
			log__printf(mosq, MOSQ_LOG_ERR, "Error: StreamOpen failed, 0x%x!", Status);
            goto Error;
		}

        log__printf(mosq, MOSQ_LOG_QUIC, "[strm][%p] Starting...", mosq->Stream);

		//
		// Starts the bidirectional stream. By default, the peer is not notified of
		// the stream being started until data is sent on the stream.
		//
        if (QUIC_FAILED(Status = MsQuic->StreamStart(mosq->Stream, QUIC_STREAM_START_FLAG_NONE))) {
			log__printf(mosq, MOSQ_LOG_ERR, "Error: StreamStart failed, 0x%x!", Status);
            MsQuic->StreamClose(mosq->Stream);
			goto Error;
		}
    }

    log__printf(mosq, MOSQ_LOG_QUIC, "[strm][%p] Sending data...", mosq->Stream);

    if (QUIC_FAILED(Status = MsQuic->StreamSend(mosq->Stream, SendBuffer, 1, QUIC_SEND_FLAG_NONE, SendBuffer))) {
        log__printf(mosq, MOSQ_LOG_ERR, "Error: StreamSend failed, 0x%x!", Status);
        free(SendBufferRaw);
        goto Error;
    }
	return (ssize_t)count;

Error:

    if (QUIC_FAILED(Status)) {
        MsQuic->ConnectionShutdown(mosq->Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }
	return 0;
}


ssize_t net__read_quic(struct mosquitto *mosq, void* buff, size_t len) {
    uint8_t* buf = (uint8_t*)buff;
	size_t pos = 0;
	int rc;
	uint8_t byte;
#ifdef WITH_BROKER
    enum mosquitto_client_state state;
#endif
	while (pos < len) {
		if (!mosq->in_packet.command){
            if (pos == len) {
                // TODO: WARNING?
                return 0;
            }
            // TODO: check boundary ?
			byte = buf[pos++];
#ifdef WITH_BROKER
			G_BYTES_RECEIVED_INC(1);
			/* Clients must send CONNECT as their first command. */
			if(!(mosq->bridge) && state == mosq_cs_connected && (byte&0xF0) != CMD_CONNECT){
				return MOSQ_ERR_PROTOCOL;
			}
#endif
            mosq->in_packet.command = byte;
		}
		if (mosq->in_packet.remaining_count <= 0){
			do{
				if(pos == len){
                    // MOSQ_ERR_CONN_LOST?
					return 0;
				}
				byte = buf[pos++];
				mosq->in_packet.remaining_count--;
				if(mosq->in_packet.remaining_count < -4){
					return MOSQ_ERR_MALFORMED_PACKET;
				}

				//G_BYTES_RECEIVED_INC(1);
                mosq->in_packet.remaining_length += (byte & 127) * mosq->in_packet.remaining_mult;
				mosq->in_packet.remaining_mult *= 128;
			}while((byte & 128) != 0);
			mosq->in_packet.remaining_count = (int8_t)(mosq->in_packet.remaining_count * -1);

#ifdef WITH_BROKER
            switch(mosq->in_packet.command & 0xF0){
                case CMD_CONNECT:
                    if(mosq->in_packet.remaining_length > 100000){ /* Arbitrary limit, make configurable */
                        return MOSQ_ERR_MALFORMED_PACKET;
                    }
                    break;

                case CMD_PUBACK:
                case CMD_PUBREC:
                case CMD_PUBREL:
                case CMD_PUBCOMP:
                case CMD_UNSUBACK:
                    if(mosq->protocol != mosq_p_mqtt5 && mosq->in_packet.remaining_length != 2){
                        return MOSQ_ERR_MALFORMED_PACKET;
                    }
                    break;

                case CMD_PINGREQ:
                case CMD_PINGRESP:
                    if(mosq->in_packet.remaining_length != 0){
                        return MOSQ_ERR_MALFORMED_PACKET;
                    }
                    break;

                case CMD_DISCONNECT:
                    if(mosq->protocol != mosq_p_mqtt5 && mosq->in_packet.remaining_length != 0){
                        return MOSQ_ERR_MALFORMED_PACKET;
                    }
                    break;
            }

            if(db.config->max_packet_size > 0 && mosq->in_packet.remaining_length+1 > db.config->max_packet_size){
                if(mosq->protocol == mosq_p_mqtt5){
                    send__disconnect(mosq, MQTT_RC_PACKET_TOO_LARGE, NULL);
                }
                return MOSQ_ERR_OVERSIZE_PACKET;
            }
#else
#endif

			if(mosq->in_packet.remaining_length > 0){
                mosq->in_packet.payload = mosquitto__malloc(mosq->in_packet.remaining_length*sizeof(uint8_t));
                if(!mosq->in_packet.payload){
                    return MOSQ_ERR_NOMEM;
                }
                mosq->in_packet.to_process = mosq->in_packet.remaining_length;
			}
		}
        //TODO: while?
		if(mosq->in_packet.to_process > 0) {
			if((uint32_t)len - pos >= mosq->in_packet.to_process){
                //G_BYTES_RECEIVED_INC(read_length);
                memcpy(&mosq->in_packet.payload[mosq->in_packet.pos], &buf[pos], mosq->in_packet.to_process);
				mosq->in_packet.pos += mosq->in_packet.to_process;
				pos += mosq->in_packet.to_process;
				mosq->in_packet.to_process = 0;
            }else{
                // TODO: compare with packet_mosq.c
				memcpy(&mosq->in_packet.payload[mosq->in_packet.pos], &buf[pos], len-pos);
				mosq->in_packet.pos += (uint32_t)(len-pos);
				mosq->in_packet.to_process -= (uint32_t)(len-pos);
				return 0;
			}
		}
		mosq->in_packet.pos = 0;

#ifdef WITH_BROKER
        G_MSGS_RECEIVED_INC(1);
        if(((mosq->in_packet.command)&0xF5) == CMD_PUBLISH){
            G_PUB_MSGS_RECEIVED_INC(1);
        }
#endif
        rc = handle__packet(mosq);

        /* Free data and reset values */
        packet__cleanup(&mosq->in_packet);

#ifdef WITH_BROKER
        keepalive__update(mosq);
#else
        pthread_mutex_lock(&mosq->msgtime_mutex);
        mosq->last_msg_in = mosquitto_time();
        pthread_mutex_unlock(&mosq->msgtime_mutex);
#endif
	}

	return rc;
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
    struct mosquitto *mosq = (struct mosquitto*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        free(Event->SEND_COMPLETE.ClientContext);
        log__printf(mosq, MOSQ_LOG_QUIC, "[strm][%p] Data sent", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        // TODO: use loop, then unify with websockets ?
        //
        // Data was received from the peer on the stream.
        //
        log__printf(mosq, MOSQ_LOG_QUIC, "[strm][%p] Data received", Stream);
        for (size_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
            //stream_packet__read(mosq, (uint8_t*)Event->RECEIVE.Buffers[i].Buffer, (uint64_t)Event->RECEIVE.Buffers[i].Length);
            net__read_quic(mosq, (void*)Event->RECEIVE.Buffers[i].Buffer, (uint64_t)Event->RECEIVE.Buffers[i].Length);
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        log__printf(mosq, MOSQ_LOG_QUIC, "[strm][%p] Peer shut down", Stream);
#ifdef WITH_BORKER
        //ServerSend(Stream);
#endif
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer aborted its send direction of the stream.
        //
        log__printf(mosq, MOSQ_LOG_QUIC, "[strm][%p] Peer aborted", Stream);
#ifdef WITH_BORKER
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
#endif
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        log__printf(mosq, MOSQ_LOG_QUIC, "[strm][%p] All done", Stream);
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
    struct mosquitto *mosq = (struct mosquitto*)Context;
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        log__printf(mosq, MOSQ_LOG_QUIC, "[conn][%p] Connected", Connection);
#ifdef WITH_BROKER
        MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
#endif
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            log__printf(mosq, MOSQ_LOG_QUIC, "[conn][%p] Successfully shut down on idle.", Connection);
        } else {
            log__printf(mosq, MOSQ_LOG_QUIC, "[conn][%p] Shut down by transport, 0x%x", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        log__printf(mosq, MOSQ_LOG_QUIC, "[conn][%p] Shut down by peer, 0x%llu", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        log__printf(mosq, MOSQ_LOG_QUIC, "[conn][%p] All done", Connection);
#ifndef WITH_BROKER
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress)
#endif
        MsQuic->ConnectionClose(Connection);
        break;
#ifdef WITH_BROKER
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        //
        // The peer has started/created a new stream. The app MUST set the
        // callback handler before returning.
        //
        log__printf(mosq, MOSQ_LOG_QUIC, "[strm][%p] Peer started", Event->PEER_STREAM_STARTED.Stream);
        mosq->Connection = Connection;
        mosq->Stream = Event->PEER_STREAM_STARTED.Stream;
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)stream_callback, mosq);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        //
        // The connection succeeded in doing a TLS resumption of a previous
        // connection's session.
        //
        log__printf(mosq, MOSQ_LOG_QUIC, "[conn][%p] Connection resumed!", Connection);
        break;
#else
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        //
        // A resumption ticket (also called New Session Ticket or NST) was
        // received from the server.
        //
        //log__printf(mosq, MOSQ_LOG_QUIC, "[conn][%p] Resumption ticket received (%u bytes):", Connection, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
		log__printf(mosq, MOSQ_LOG_QUIC, "[conn][%p] Skip resumption binary", Connection);
        for (uint32_t i = 0; i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++) {
            //log__printf(mosq, MOSQ_LOG_QUIC, "%.2X", (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
        }
        break;
#endif
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}


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
    //const char* ResumptionTicketString = NULL;

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
        MsQuic->RegistrationShutdown(*Registration, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        *Registration = NULL;
    }
    return 0;
}

int quic_disconnect(struct mosquitto *mosq)
{
    return quic_close_internal(&mosq->Registration, &mosq->Configuration, &mosq->Connection, &mosq->Stream);
}

 #endif