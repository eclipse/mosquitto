#include "common.h"
#include "mqtt_protocol.h"
// To avoid segv on server
#include "memory_mosq.h"

#ifdef WITH_BROKER
#  include "sys_tree.h"
#  include "mosquitto_broker_internal.h"
#else
#  include "client.h"
#endif

#include <msquic.h>
#include <msquic_posix.h>

const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };

int
quic_init(HQUIC *Registration, const struct mosquitto__config *conf)
{
    // TODO: load config from conf.
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    //
    // Open a handle to the library and get the API function table.
    //
    if (QUIC_FAILED(Status = MsQuicOpen(&MsQuic))) {
        printf("MsQuicOpen failed, 0x%x!\n", Status);
        return Status;
    }

    //
    // Create a registration for the app's connections.
    //
	const QUIC_REGISTRATION_CONFIG RegConfig = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        return Status;
    }

	return 0;
}


int
quic_send(struct mosquitto *mosq, const void *buf, size_t count)
{

    QUIC_STATUS Status;
    uint8_t* SendBufferRaw;
    QUIC_BUFFER* SendBuffer;

    // WARN: when is this freed?
	SendBufferRaw = (uint8_t*)malloc(sizeof(QUIC_BUFFER) + count);
    if (SendBufferRaw == NULL) {
        // TODO: log warning
        printf("SendBuffer allocation failed!\n");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = count;
    memcpy(SendBuffer->Buffer, buf, count);

    printf("[strm][%p] Sending data...\n", mosq->Stream);

	fprintf(stderr, "quic_send [");
	for(int i = 0; i < count; i++) {
		fprintf(stderr, "%d, ", (SendBuffer->Buffer)[i]);
	}
	fprintf(stderr, "]\n");
    if (QUIC_FAILED(Status = MsQuic->StreamSend(mosq->Stream, SendBuffer, 1, QUIC_SEND_FLAG_NONE, SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        free(SendBufferRaw);
        goto Error;
    }
	return SendBuffer->Length;

Error:

    if (QUIC_FAILED(Status)) {
        MsQuic->ConnectionShutdown(mosq->Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }
	return 0;
}


int stream_packet__read(struct mosquitto *mosq, uint8_t* buf, size_t len) {
	size_t pos = 0;
	int rc;
	uint8_t byte;
    enum mosquitto_client_state state;
	while (pos < len) {
		fprintf(stderr, "[strm] 1 pos=%d/%d\n", pos, len);
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
		fprintf(stderr, "[strm] 2 pos=%d/%d\n", pos, len);
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
			fprintf(stderr, "[strm] 3 pos=%d/%d\n", pos, len);
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
			    fprintf(stderr, "[strm] 4 pos=%d/%d\n", pos, len);
            }else{
                // TODO: compare with packet_mosq.c
				memcpy(&mosq->in_packet.payload[mosq->in_packet.pos], &buf[pos], len-pos);
				mosq->in_packet.pos += (uint32_t)(len-pos);
				mosq->in_packet.to_process -= (uint32_t)(len-pos);
				fprintf(stderr, "[strm] 4 pos=%d/%d early return\n", pos, len);
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
        fprintf(stderr, "[strm] handle__packet\n");
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
        // TODO: use loop, then unify with websockets ?
        //
        // Data was received from the peer on the stream.
        //
        printf("[strm][%p] Data received\n", Stream);
        for (int i = 0; i < Event->RECEIVE.BufferCount; i++) {
			int len =Event->RECEIVE.Buffers[i].Length;
            printf("[strm][%p] (%d/%d): %d[%s]\n", Stream, i+1, Event->RECEIVE.BufferCount, len, (char*)Event->RECEIVE.Buffers[i].Buffer);
            buf = (uint8_t*)Event->RECEIVE.Buffers[i].Buffer;
            fprintf(stderr, "Received len=%d [", len);
            for (int j = 0; j < len; j++) {
                fprintf(stderr, "%d, ", buf[j]);
            }
			fprintf(stderr, "] after\n");
            stream_packet__read(mosq, buf, len);
        }
        fprintf(stderr, "[strm] handle command end\n");
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer shut down\n", Stream);
#ifdef WITH_BORKER
        //ServerSend(Stream);
#endif
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", Stream);
#ifdef WITH_BORKER
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
#endif
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
#ifdef WITH_BROKER
        MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
#else
		Connected = true;

        // TODO: wrap as function for starting stream
        connection_context = (struct libmsquic_mqtt*)Context;
		QUIC_STATUS Status;

		//
		// Create/allocate a new bidirectional stream. The stream is just allocated
		// and no QUIC stream identifier is assigned until it's started.
		//
        if (QUIC_FAILED(Status = MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, stream_callback, connection_context, &connection_context->mosq->Stream))) {
			printf("StreamOpen failed, 0x%x!\n", Status);
			return;
		}

		printf("[strm][%p] Starting...\n", connection_context->mosq->Stream);

		//
		// Starts the bidirectional stream. By default, the peer is not notified of
		// the stream being started until data is sent on the stream.
		//
		if (QUIC_FAILED(Status = MsQuic->StreamStart(connection_context->mosq->Stream, QUIC_STREAM_START_FLAG_NONE))) {
			printf("StreamStart failed, 0x%x!\n", Status);
			MsQuic->StreamClose(connection_context->mosq->Stream);
			return;
		}
#endif
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
#else
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        //
        // A resumption ticket (also called New Session Ticket or NST) was
        // received from the server.
        //
        printf("[conn][%p] Resumption ticket received (%u bytes):\n", Connection, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
		printf("[conn][%p] Skip resumption binary");
        for (uint32_t i = 0; i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++) {
            //printf("%.2X", (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
        }
        printf("\n");
        break;
#endif
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}