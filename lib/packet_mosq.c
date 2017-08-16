/*
Copyright (c) 2009-2016 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
   Tatsuzo Osawa - Add mqtt version 5.   
*/

#include <assert.h>
#include <errno.h>
#include <string.h>

#ifdef WITH_BROKER
#  include "mosquitto_broker_internal.h"
#  ifdef WITH_WEBSOCKETS
#    include <libwebsockets.h>
#  endif
#else
#  include "read_handle.h"
#endif

#include "logging_mosq.h"
#include "memory_mosq.h"
#include "mqtt3_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "read_handle.h"
#ifdef WITH_BROKER
#  include "sys_tree.h"
#else
#  define G_BYTES_RECEIVED_INC(A)
#  define G_BYTES_SENT_INC(A)
#  define G_MSGS_SENT_INC(A)
#  define G_PUB_MSGS_SENT_INC(A)
#endif

int packet__alloc(struct mosquitto__packet *packet)
{
	uint8_t remaining_bytes[5], byte;
	uint32_t remaining_length;
	int i;

	assert(packet);

	remaining_length = packet->remaining_length;
	packet->payload = NULL;
	packet->remaining_count = 0;
	do{
		byte = remaining_length % 128;
		remaining_length = remaining_length / 128;
		/* If there are more digits to encode, set the top bit of this digit */
		if(remaining_length > 0){
			byte = byte | 0x80;
		}
		remaining_bytes[packet->remaining_count] = byte;
		packet->remaining_count++;
	}while(remaining_length > 0 && packet->remaining_count < 5);
	if(packet->remaining_count == 5) return MOSQ_ERR_PAYLOAD_SIZE;
	packet->packet_length = packet->remaining_length + 1 + packet->remaining_count;
#ifdef WITH_WEBSOCKETS
	packet->payload = mosquitto__malloc(sizeof(uint8_t)*packet->packet_length + LWS_SEND_BUFFER_PRE_PADDING + LWS_SEND_BUFFER_POST_PADDING);
#else
	packet->payload = mosquitto__malloc(sizeof(uint8_t)*packet->packet_length);
#endif
	if(!packet->payload) return MOSQ_ERR_NOMEM;

	packet->payload[0] = packet->command;
	for(i=0; i<packet->remaining_count; i++){
		packet->payload[i+1] = remaining_bytes[i];
	}
	packet->pos = 1 + packet->remaining_count;

	return MOSQ_ERR_SUCCESS;
}

void packet__cleanup(struct mosquitto__packet *packet)
{
	if(!packet) return;

	/* Free data and reset values */
	packet->command = 0;
	packet->remaining_count = 0;
	packet->remaining_mult = 1;
	packet->remaining_length = 0;
	mosquitto__free(packet->payload);
	packet->payload = NULL;
	packet->to_process = 0;
	packet->pos = 0;
}

int packet__queue(struct mosquitto *mosq, struct mosquitto__packet *packet)
{
#ifndef WITH_BROKER
	char sockpair_data = 0;
#endif
	assert(mosq);
	assert(packet);

	packet->pos = 0;
	packet->to_process = packet->packet_length;

	packet->next = NULL;
	pthread_mutex_lock(&mosq->out_packet_mutex);
	if(mosq->out_packet){
		mosq->out_packet_last->next = packet;
	}else{
		mosq->out_packet = packet;
	}
	mosq->out_packet_last = packet;
	pthread_mutex_unlock(&mosq->out_packet_mutex);
#ifdef WITH_BROKER
#  ifdef WITH_WEBSOCKETS
	if(mosq->wsi){
		libwebsocket_callback_on_writable(mosq->ws_context, mosq->wsi);
		return 0;
	}else{
		return packet__write(mosq);
	}
#  else
	return packet__write(mosq);
#  endif
#else

	/* Write a single byte to sockpairW (connected to sockpairR) to break out
	 * of select() if in threaded mode. */
	if(mosq->sockpairW != INVALID_SOCKET){
#ifndef WIN32
		if(write(mosq->sockpairW, &sockpair_data, 1)){
		}
#else
		send(mosq->sockpairW, &sockpair_data, 1, 0);
#endif
	}

	if(mosq->in_callback == false && mosq->threaded == false){
		return packet__write(mosq);
	}else{
		return MOSQ_ERR_SUCCESS;
	}
#endif
}


int packet__read_byte(struct mosquitto__packet *packet, uint8_t *byte)
{
	assert(packet);
	if(packet->pos+1 > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	*byte = packet->payload[packet->pos];
	packet->pos++;

	return MOSQ_ERR_SUCCESS;
}


void packet__write_byte(struct mosquitto__packet *packet, uint8_t byte)
{
	assert(packet);
	assert(packet->pos+1 <= packet->packet_length);

	packet->payload[packet->pos] = byte;
	packet->pos++;
}


int packet__read_bytes(struct mosquitto__packet *packet, void *bytes, uint32_t count)
{
	assert(packet);
	if(packet->pos+count > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	memcpy(bytes, &(packet->payload[packet->pos]), count);
	packet->pos += count;

	return MOSQ_ERR_SUCCESS;
}


void packet__write_bytes(struct mosquitto__packet *packet, const void *bytes, uint32_t count)
{
	assert(packet);
	assert(packet->pos+count <= packet->packet_length);

	memcpy(&(packet->payload[packet->pos]), bytes, count);
	packet->pos += count;
}


int packet__read_string(struct mosquitto__packet *packet, char **str)
{
	uint16_t len;
	int rc;

	assert(packet);
	rc = packet__read_uint16(packet, &len);
	if(rc) return rc;

	if(packet->pos+len > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	*str = mosquitto__malloc(len+1);
	if(*str){
		memcpy(*str, &(packet->payload[packet->pos]), len);
		(*str)[len] = '\0';
		packet->pos += len;
	}else{
		return MOSQ_ERR_NOMEM;
	}

	return MOSQ_ERR_SUCCESS;
}


void packet__write_string(struct mosquitto__packet *packet, const char *str, uint16_t length)
{
	assert(packet);
	packet__write_uint16(packet, length);
	packet__write_bytes(packet, str, length);
}


int packet__read_uint16(struct mosquitto__packet *packet, uint16_t *word)
{
	uint8_t msb, lsb;

	assert(packet);
	if(packet->pos+2 > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	msb = packet->payload[packet->pos];
	packet->pos++;
	lsb = packet->payload[packet->pos];
	packet->pos++;

	*word = (msb<<8) + lsb;

	return MOSQ_ERR_SUCCESS;
}


void packet__write_uint16(struct mosquitto__packet *packet, uint16_t word)
{
	packet__write_byte(packet, MOSQ_MSB(word));
	packet__write_byte(packet, MOSQ_LSB(word));
}

// Read variable byte integer for mqtt version 5
int packet__read_variable(struct mosquitto__packet *packet, varint_t *variable)
{
	int multiplier = 1;
	int pos = 0;
	uint8_t encodebyte;

	assert(packet);
	*variable = 0;

	do {
		if(packet->pos+pos+1 > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

		encodebyte = packet->payload[packet->pos+pos];
		*variable += (encodebyte & 127) * multiplier;
		if(multiplier > 128*128*128){
			return MOSQ_ERR_PROTOCOL;
		}
		multiplier *= 128;
		pos++;
	} while((encodebyte & 128) != 0);

	packet->pos += pos;
	return MOSQ_ERR_SUCCESS;
}

// Write variable byte integer for mqtt version 5
void packet__write_variable(struct mosquitto__packet *packet, varint_t variable)
{
	uint8_t encodebyte;

	assert(packet);
	assert(variable <= MQTT5_MAX_VARIABLE_BYTE_INT);

	do {
		encodebyte = variable % 128;
		variable /= 128;
		if(variable > 0){
			encodebyte |= 128;
		}
		packet__write_byte(packet, encodebyte);		
	} while(variable > 0);
}

size_t variable_len(varint_t variable)
{
	if(variable < 0) return 0;
	if(variable < 128) return 1;
	if(variable < 16384) return 2;
	if(variable < 2097152) return 3;
	if(variable < 268435455) return 4;
	return 0;
}

const char *v5_property_name[] = {
	"",
	"PAYLOAD_FORMAT_INDICATOR",  // 1
    "PUBLICATION_EXPIRY_INTERVAL",
	"CONTENT_TYPE",
	"", "", "", "",
	"RESPONSE_TOPIC",  // 8
	"CORRELATION_DATA",
	"",
	"subscription_identifiers",  // 11
	"", "", "", "", "",
	"SESSION_EXPIRY_INTERVAL",  // 17
	"ASSIGNED_CLIENT_IDENTIFIER",
	"SERVER_KEEP_ALIVE",
	"",
	"AUTHENTICATION_METHOD",  // 21
	"AUTHENTICATION_DATA",
	"REQUEST_PROBLEM_INFORMATION",
	"WILL_DELAY_INTERVAL",
	"REQUEST_RESPONSE_INFORMATION",
	"RESPONSE_INFORMATION",
	"",
	"SERVER_REFERENCE",  // 28
	"", "",
	"REASON_STRING",  // 31
	"",
	"RECEIVE_MAXIMUM",  // 33
	"TOPIC_ALIAS_MAXIMUM",
	"TOPIC_ALIAS",
	"MAXIMUM_QOS",
	"RETAIN_AVAILABLE",
	"USER_PROPERTY",
	"MAXIMUM_PACKET_SIZE",
	"WILDCARD_SUBSCRIPTION_AVAILABLE",
	"SUBSCRIPTION_IDENTIFIER_AVAILABLE",
	"SHARED_SUBSCRIPTION_AVAILABLE",
};

const char *command_name[] = {
	"undefined",
	"CONNECT",
	"CONNACK",
	"PUBLISH",
	"PUBACK",
	"PUBREC",
	"PUBREL",
	"PUBCOMP",
	"SUBSCRIBE",
	"SUBACK",
	"UNSUBSCRIBE",
	"UNSUBACK",
	"PINGREQ",
	"PINGRESP",
	"DISCONNECT",
	"AUTH",
};

#define PACKET_READ_PROPERTY_1(m, p, d, isd, pos, id)                            \
do {                                                                             \
  if(isd)return MQTT5_RC_PROTOCOL_ERROR;                                         \
  if(packet__read_byte((p), &(d)))return MQTT5_RC_MALFORMED_PACKET;              \
  (isd) = true;                                                                  \
  (pos)++;                                                                       \
  log__printf(m, MOSQ_LOG_DEBUG, "Read v5 property: %s = %d",                    \
  	v5_property_name[id], (d));                                                  \
} while(0)

#define PACKET_READ_PROPERTY_2(m, p, d, isd, pos, id)                            \
do {                                                                             \
  if(isd)return MQTT5_RC_PROTOCOL_ERROR;                                         \
  if(packet__read_uint16((p), &(d)))return MQTT5_RC_MALFORMED_PACKET;            \
  isd = true;                                                                    \
  (pos) += 2;                                                                    \
  log__printf(m, MOSQ_LOG_DEBUG, "Read v5 property: %s = %d",                    \
  	v5_property_name[id], (d));                                                  \
} while(0)

#define PACKET_READ_PROPERTY_4(m, p, d, isd, pos, id)                            \
do {                                                                             \
  if(isd)return MQTT5_RC_PROTOCOL_ERROR;                                         \
  if(packet__read_bytes((p), &(d), 4))return MQTT5_RC_MALFORMED_PACKET;          \
  isd = true;                                                                    \
  (pos) += 4;                                                                    \
  log__printf(m, MOSQ_LOG_DEBUG, "Read v5 property: %s = %d",                    \
  	v5_property_name[id], (d));                                                  \
} while(0)

#define PACKET_READ_PROPERTY_VAR_DUP(m, p, d, pos, id)                           \
do {                                                                             \
  if(packet__read_variable((p), &(d)))return MQTT5_RC_MALFORMED_PACKET;          \
  (pos) += variable_len(d);                                                      \
  log__printf(m, MOSQ_LOG_DEBUG, "Read v5 property: %s = %d",                    \
  	v5_property_name[id], (d));                                                  \
} while(0)

#define PACKET_READ_PROPERTY_VAR(m, p, d, isd, pos, id)                          \
do {                                                                             \
  if(isd)return MQTT5_RC_PROTOCOL_ERROR;                                         \
  PACKET_READ_PROPERTY_VAR_DUP(m, p, d, pos, id);                                \
  isd = true;                                                                    \
} while(0)

#define PACKET_READ_PROPERTY_BIN(m, p, d, l, pos, id)                            \
do {                                                                             \
  if((l)!=0)return MQTT5_RC_PROTOCOL_ERROR;                                      \
  if(packet__read_uint16((p), &(l))){                                            \
  	(l) = 0;                                                                     \
  	return MQTT5_RC_MALFORMED_PACKET;                                            \
  }                                                                              \
  (d) = mosquitto__malloc(l);                                                    \
  if(!(d)){                                                                      \
  	(l) = 0;                                                                     \
  	return MQTT5_RC_UNSPECIFIED_ERROR;                                           \
  }                                                                              \
  if(packet__read_bytes((p), (d), (l))){                                         \
  	mosquitto__free(d);                                                          \
  	(d) = NULL;                                                                  \
  	(l) = 0;                                                                     \
  	return MQTT5_RC_MALFORMED_PACKET;                                            \
  }                                                                              \
  (pos) += (l)+2;                                                                \
  log__printf(m, MOSQ_LOG_DEBUG, "Read v5 property: %s, %d bytes",               \
  	v5_property_name[id], (l));                                                  \
} while(0)

#define PACKET_READ_PROPERTY_STR_DUP(m, p, d, pos, id)                           \
do {                                                                             \
  if(packet__read_string(p, &(d))){                                              \
  	mosquitto__free(d);                                                          \
  	(d) = NULL;                                                                  \
  	return MQTT5_RC_MALFORMED_PACKET;                                            \
  }                                                                              \
  (pos) += strlen(d)+2;                                                          \
  log__printf(m, MOSQ_LOG_DEBUG, "Read v5 property: %s = %s",                    \
  	v5_property_name[id], (d));                                                  \
} while(0)

#define PACKET_READ_PROPERTY_STR(m, p, d, pos, id)                               \
do {                                                                             \
  if(d) return MQTT5_RC_PROTOCOL_ERROR;                                          \
  PACKET_READ_PROPERTY_STR_DUP(m, p, d, pos, id);                                \
} while(0)

// Read properties for mqtt version 5
int packet__read_property(struct mosquitto *mosq, struct mosquitto__packet *packet, struct mosquitto_v5_property *property, int command)
{
	varint_t packet__property_length;
	int property_id;
	int pos = 0;

	if(!property) return MQTT5_RC_UNSPECIFIED_ERROR;
	memset(property, 0, sizeof(struct mosquitto_v5_property));

	if(packet__read_variable(packet, &packet__property_length)){
		log__printf(mosq, MOSQ_LOG_INFO, "Read v5 property length invalid.");
		return MQTT5_RC_MALFORMED_PACKET;
	}
	log__printf(mosq, MOSQ_LOG_DEBUG, "Read v5 property length: %d on command: %s", packet__property_length, command_name[command >> 4]);

	while(pos < packet__property_length){
		if(packet__read_variable(packet, &property_id)){
			return MQTT5_RC_MALFORMED_PACKET;
		}
		pos += variable_len(property_id);

		switch(property_id){
			case MQTT5_P_PAYLOAD_FORMAT_INDICATOR:
				if(command != PUBLISH) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_1(mosq, packet, property->payload_format_indicator, property->is_payload_format_indicator, pos, property_id);
				break;
			case MQTT5_P_PUBLICATION_EXPIRY_INTERVAL:
				if(command != PUBLISH) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_4(mosq, packet, property->publication_expiry_interval, property->is_publication_expiry_interval, pos, property_id);
				break;
			case MQTT5_P_CONTENT_TYPE:
				if(command != PUBLISH) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_STR(mosq, packet, property->content_type, pos, property_id);
				break;
			case MQTT5_P_RESPONSE_TOPIC:
				if(command != PUBLISH) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_STR(mosq, packet, property->response_topic, pos, property_id);
				break;
			case MQTT5_P_CORRELATION_DATA:
				if(command != PUBLISH) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_BIN(mosq, packet, property->correlation_data, property->correlation_data_len, pos, property_id);
				break;
			case MQTT5_P_SUBSCRIPTION_IDENTIFIER:
				if((command != PUBLISH) && (command != SUBSCRIBE)) return MQTT5_RC_MALFORMED_PACKET;
				property->subscription_identifiers = mosquitto__realloc(property->subscription_identifiers, sizeof(varint_t) * (property->subscription_identifiers_count));
				if(!property->subscription_identifiers) return MQTT5_RC_UNSPECIFIED_ERROR;
				PACKET_READ_PROPERTY_VAR_DUP(mosq, packet, property->subscription_identifiers[property->subscription_identifiers_count], pos, property_id);
				property->subscription_identifiers_count++;
				break;
			case MQTT5_P_SESSION_EXPIRY_INTERVAL:
				if((command != CONNECT) && (command != DISCONNECT)) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_4(mosq, packet, property->session_expiry_interval, property->is_session_expiry_interval, pos, property_id);
				break;
			case MQTT5_P_ASSIGNED_CLIENT_IDENTIFIER:
				if(command != CONNACK) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_STR(mosq, packet, property->assigned_client_identifier, pos, property_id);
				break;
			case MQTT5_P_SERVER_KEEP_ALIVE:
				if(command != CONNACK) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_2(mosq, packet, property->server_keep_alive, property->is_server_keep_alive, pos, property_id);
				break;
			case MQTT5_P_AUTHENTICATION_METHOD:
				if((command != CONNECT) && (command != CONNACK) && (command != AUTH)) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_STR(mosq, packet, property->authentication_method, pos, property_id);
				break;
			case MQTT5_P_AUTHENTICATION_DATA:
				if((command != CONNECT) && (command != CONNACK) && (command != AUTH)) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_BIN(mosq, packet, property->authentication_data, property->authentication_data_len, pos, property_id);
				break;
			case MQTT5_P_REQUEST_PROBLEM_INFORMATION:
				if(command != CONNECT) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_1(mosq, packet, property->request_problem_information, property->is_request_problem_information, pos, property_id);
				break;
			case MQTT5_P_WILL_DELAY_INTERVAL:
				if(command != CONNECT) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_4(mosq, packet, property->will_delay_interval, property->is_will_delay_interval, pos, property_id);
				break;
			case MQTT5_P_REQUEST_RESPONSE_INFORMATION:
				if(command != CONNECT) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_1(mosq, packet, property->request_response_information, property->is_request_response_information, pos, property_id);
				break;
			case MQTT5_P_RESPONSE_INFORMATION:
				if(command != CONNACK) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_STR(mosq, packet, property->response_information, pos, property_id);
				break;
			case MQTT5_P_SERVER_REFERENCE:
				if((command != CONNACK) && (command != DISCONNECT)) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_STR(mosq, packet, property->server_reference, pos, property_id);
				break;
			case MQTT5_P_REASON_STRING:
				if((command != CONNACK) && (command != PUBACK) && (command != PUBREC) &&
				   (command != PUBREL) && (command != PUBCOMP) && (command != SUBACK) &&
				   (command != UNSUBACK) && (command != DISCONNECT) && (command != AUTH)) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_STR(mosq, packet, property->reason_string, pos, property_id);
				break;
			case MQTT5_P_RECEIVE_MAXIMUM:
				if((command != CONNECT) && (command != CONNACK)) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_2(mosq, packet, property->receive_maximum, property->is_receive_maximum, pos, property_id);
				break;
			case MQTT5_P_TOPIC_ALIAS_MAXIMUM:
				if((command != CONNECT) && (command != CONNACK)) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_2(mosq, packet, property->topic_alias_maximum, property->is_topic_alias_maximum, pos, property_id);
				break;
			case MQTT5_P_TOPIC_ALIAS:
				if(command != PUBLISH) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_2(mosq, packet, property->topic_alias, property->is_topic_alias, pos, property_id);
				break;
			case MQTT5_P_MAXIMUM_QOS:
				if(command != CONNACK) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_1(mosq, packet, property->maximum_qos, property->is_maximum_qos, pos, property_id);
				break;
			case MQTT5_P_RETAIN_AVAILABLE:
				if(command != CONNACK) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_1(mosq, packet, property->retain_available, property->is_retain_available, pos, property_id);
				break;
			case MQTT5_P_USER_PROPERTY:
				if((command != CONNECT) && (command != CONNACK) && (command != PUBLISH) &&
				   (command != PUBACK) && (command != PUBREC) && (command != PUBREL) &&
				   (command != PUBCOMP) && (command != SUBACK) && (command != UNSUBACK) &&
				   (command != DISCONNECT) && (command != AUTH)) return MQTT5_RC_MALFORMED_PACKET;
				property->user_property_keys = mosquitto__realloc(property->user_property_keys, sizeof(char*) * (property->user_propertys_count));
				if(!property->user_property_keys) return MQTT5_RC_UNSPECIFIED_ERROR;
				PACKET_READ_PROPERTY_STR_DUP(mosq, packet, property->user_property_keys[property->user_propertys_count], pos, property_id);
				property->user_property_values = mosquitto__realloc(property->user_property_values, sizeof(char*) * (property->user_propertys_count));
				if(!property->user_property_values) return MQTT5_RC_UNSPECIFIED_ERROR;
				PACKET_READ_PROPERTY_STR_DUP(mosq, packet, property->user_property_values[property->user_propertys_count], pos, property_id);
				property->user_propertys_count++;
				break;
			case MQTT5_P_MAXIMUM_PACKET_SIZE:
				if((command != CONNECT) && (command != CONNACK)) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_4(mosq, packet, property->maximum_packet_size, property->is_maximum_packet_size, pos, property_id);
				break;
			case MQTT5_P_WILDCARD_SUBSCRIPTION_AVAILABLE:
				if(command != CONNACK) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_1(mosq, packet, property->wildcard_subscription_available, property->is_wildcard_subscription_available, pos, property_id);
				break;
			case MQTT5_P_SUBSCRIPTION_IDENTIFIER_AVAILABLE:
				if(command != CONNACK) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_1(mosq, packet, property->subscription_identifier_available, property->is_subscription_identifier_available, pos, property_id);
				break;
			case MQTT5_P_SHARED_SUBSCRIPTION_AVAILABLE:
				if(command != CONNACK) return MQTT5_RC_MALFORMED_PACKET;
				PACKET_READ_PROPERTY_1(mosq, packet, property->shared_subscription_available, property->is_shared_subscription_available, pos, property_id);
				break;
			default:
				log__printf(mosq, MOSQ_LOG_INFO, "Read v5 property unsupported: %d", property_id);
				return MQTT5_RC_MALFORMED_PACKET;
		}
	}
	if(pos > packet__property_length){
		log__printf(mosq, MOSQ_LOG_INFO, "Read v5 property length and actual size mismatched.");
		return MQTT5_RC_MALFORMED_PACKET;
	}

	return MQTT5_RC_SUCCESS;
}

varint_t packet__property_len(struct mosquitto_v5_property *property)
{
	int i;
	if(!property) return 0;

	varint_t l = 0;
	if(property->is_payload_format_indicator) l += 2;
	if(property->is_publication_expiry_interval) l += 5;
	if(property->content_type) l += strlen(property->content_type) + 3;
	if(property->response_topic) l += strlen(property->response_topic) + 3;
	if(property->correlation_data_len > 0) l += property->correlation_data_len + 3;
	if(property->subscription_identifiers_count > 0){
		for(i = 0; i < property->subscription_identifiers_count; i++){
			l += variable_len(property->subscription_identifiers[i]) + 1;
		}
	}
	if(property->is_session_expiry_interval) l += 5;
	if(property->assigned_client_identifier) l += strlen(property->assigned_client_identifier) + 1;
	if(property->is_server_keep_alive) l += 3;
	if(property->authentication_method) l += strlen(property->authentication_method) + 3;
	if(property->authentication_data_len > 0) l += property->authentication_data_len + 3;
	if(property->is_request_problem_information) l += 2;
	if(property->is_will_delay_interval) l += 5;
	if(property->is_request_response_information) l += 2;
	if(property->response_information) l += strlen(property->response_information) + 3;
	if(property->server_reference) l += strlen(property->server_reference) + 3;
	if(property->reason_string) l += strlen(property->reason_string) + 3;
	if(property->is_receive_maximum) l += 3;
	if(property->is_topic_alias_maximum) l += 3;
	if(property->is_topic_alias) l += 3;
	if(property->is_maximum_qos) l += 2;
	if(property->is_retain_available) l += 2;
	if(property->user_propertys_count > 0){
		for(i = 0; i < property->user_propertys_count; i++){
			l++;
			l += strlen(property->user_property_keys[i]) + 2;
			l += strlen(property->user_property_values[i]) + 2;
		}
	}
	if(property->is_maximum_packet_size) l += 5;
	if(property->is_wildcard_subscription_available) l += 2;
	if(property->is_subscription_identifier_available) l += 2;
	if(property->is_shared_subscription_available) l += 2;

	return l;
}

// Write properties for mqtt version 5
void packet__write_property(struct mosquitto *mosq, struct mosquitto__packet *packet, struct mosquitto_v5_property *property, int command)
{
	int start_pos, i;
	varint_t len;
	assert(packet);

	len = packet__property_len(property); // len = 0 even if property == NULL
	packet__write_variable(packet, len);
	log__printf(mosq, MOSQ_LOG_DEBUG, "Writing v5 property length: %d on command: %s", len, command_name[command >> 4]);
	if(len == 0) return;

	start_pos = packet->pos;

	if(property->is_payload_format_indicator){
		assert(command == PUBLISH);
		packet__write_variable(packet, MQTT5_P_PAYLOAD_FORMAT_INDICATOR);
		packet__write_byte(packet, property->payload_format_indicator);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: PAYLOAD_FORMAT_INDICATOR = %d", property->payload_format_indicator);
	}
	if(property->is_publication_expiry_interval){
		assert(command == PUBLISH);
		packet__write_variable(packet, MQTT5_P_PUBLICATION_EXPIRY_INTERVAL);
		packet__write_bytes(packet, &property->publication_expiry_interval, 4);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: PUBLICATION_EXPIRY_INTERVAL = %d", property->publication_expiry_interval);
	}
	if(property->content_type){
		assert(command == PUBLISH);
		packet__write_variable(packet, MQTT5_P_CONTENT_TYPE);
		packet__write_string(packet, property->content_type, strlen(property->content_type));
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: CONTENT_TYPE = %s", property->content_type);
	}
	if(property->response_topic){
		assert(command == PUBLISH);
		packet__write_variable(packet, MQTT5_P_RESPONSE_TOPIC);
		packet__write_string(packet, property->response_topic, strlen(property->response_topic));
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: RESPONSE_TOPIC = %s", property->response_topic);
	}
	if(property->correlation_data_len > 0){
		assert(command == PUBLISH);
		packet__write_variable(packet, MQTT5_P_CORRELATION_DATA);
		packet__write_bytes(packet, property->correlation_data, property->correlation_data_len);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: CORRELATION_DATA, %d bytes", property->correlation_data_len);
	}
	if(property->subscription_identifiers_count > 0){
		assert((command == PUBLISH) || (command == SUBSCRIBE));
		for(i = 0; i < property->subscription_identifiers_count; i++){
			assert(property->subscription_identifiers[i]);
			packet__write_variable(packet, MQTT5_P_SUBSCRIPTION_IDENTIFIER);
			packet__write_variable(packet, property->subscription_identifiers[i]);
			log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: subscription_identifiers = %d", property->subscription_identifiers[i]);
		}
	}
	if(property->is_session_expiry_interval){
		assert((command == CONNECT) || (command == DISCONNECT));
		packet__write_variable(packet, MQTT5_P_SESSION_EXPIRY_INTERVAL);
		packet__write_bytes(packet, &property->session_expiry_interval, 4);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: SESSION_EXPIRY_INTERVAL = %d", property->session_expiry_interval);
	}
	if(property->assigned_client_identifier){
		assert(command == CONNACK);
		packet__write_variable(packet, MQTT5_P_ASSIGNED_CLIENT_IDENTIFIER);
		packet__write_string(packet, property->assigned_client_identifier, strlen(property->assigned_client_identifier));
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: ASSIGNED_CLIENT_IDENTIFIER = %s", property->assigned_client_identifier);
	}
	if(property->is_server_keep_alive){
		assert(command == CONNACK);
		packet__write_variable(packet, MQTT5_P_SERVER_KEEP_ALIVE);
		packet__write_uint16(packet, property->server_keep_alive);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: SERVER_KEEP_ALIVE = %d", property->server_keep_alive);
	}
	if(property->authentication_method){
		assert((command == CONNECT) || (command == CONNACK) || (command == AUTH));
		packet__write_variable(packet, MQTT5_P_AUTHENTICATION_METHOD);
		packet__write_string(packet, property->authentication_method, strlen(property->authentication_method));
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: AUTHENTICATION_METHOD = %s", property->authentication_method);
	}
	if(property->authentication_data_len > 0){
		assert((command == CONNECT) || (command == CONNACK) || (command == AUTH));
		packet__write_variable(packet, MQTT5_P_AUTHENTICATION_DATA);
		packet__write_bytes(packet, property->authentication_data, property->authentication_data_len);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: AUTHENTICATION_DATA, %d bytes", property->authentication_data_len);
	}
	if(property->is_request_problem_information){
		assert(command == CONNECT);
		packet__write_variable(packet, MQTT5_P_REQUEST_PROBLEM_INFORMATION);
		packet__write_byte(packet, property->request_problem_information);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: REQUEST_PROBLEM_INFORMATION = %d", property->request_problem_information);
	}
	if(property->is_will_delay_interval){
		assert(command == CONNECT);
		packet__write_variable(packet, MQTT5_P_WILL_DELAY_INTERVAL);
		packet__write_bytes(packet, &property->will_delay_interval, 4);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: WILL_DELAY_INTERVAL = %d", property->will_delay_interval);
	}
	if(property->is_request_response_information){
		assert(command == CONNECT);
		packet__write_variable(packet, MQTT5_P_REQUEST_RESPONSE_INFORMATION);
		packet__write_byte(packet, property->request_response_information);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: REQUEST_RESPONSE_INFORMATION = %d", property->request_response_information);
	}
	if(property->response_information){
		assert(command == CONNACK);
		packet__write_variable(packet, MQTT5_P_RESPONSE_INFORMATION);
		packet__write_string(packet, property->response_information, strlen(property->response_information));
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: RESPONSE_INFORMATION = %s", property->response_information);
	}
	if(property->server_reference){
		assert((command == CONNACK) || (command == DISCONNECT));
		packet__write_variable(packet, MQTT5_P_SERVER_REFERENCE);
		packet__write_string(packet, property->server_reference, strlen(property->server_reference));
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: SERVER_REFERENCE = %s", property->server_reference);
	}
	if(property->reason_string){
		assert((command == CONNACK) || (command == PUBACK) || (command == PUBREC) ||
			   (command == PUBREL) || (command == PUBCOMP) || (command == SUBACK) ||
			   (command == UNSUBACK) || (command == DISCONNECT) || (command == AUTH));
		packet__write_variable(packet, MQTT5_P_REASON_STRING);
		packet__write_string(packet, property->reason_string, strlen(property->reason_string));
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: REASON_STRING = %s", property->reason_string);
	}
	if(property->is_receive_maximum){
		assert((command == CONNECT) || (command == CONNACK));
		packet__write_variable(packet, MQTT5_P_RECEIVE_MAXIMUM);
		packet__write_uint16(packet, property->receive_maximum);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: RECEIVE_MAXIMUM = %d", property->receive_maximum);
	}
	if(property->is_topic_alias_maximum){
		assert((command == CONNECT) || (command == CONNACK));
		packet__write_variable(packet, MQTT5_P_TOPIC_ALIAS_MAXIMUM);
		packet__write_uint16(packet, property->topic_alias_maximum);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: TOPIC_ALIAS_MAXIMUM = %d", property->topic_alias_maximum);
	}
	if(property->is_topic_alias){
		assert(command == PUBLISH);
		packet__write_variable(packet, MQTT5_P_TOPIC_ALIAS);
		packet__write_uint16(packet, property->topic_alias);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: TOPIC_ALIAS = %d", property->topic_alias);
	}
	if(property->is_maximum_qos){
		assert(command == CONNACK);
		packet__write_variable(packet, MQTT5_P_MAXIMUM_QOS);
		packet__write_byte(packet, property->maximum_qos);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: MAXIMUM_QOS = %d", property->maximum_qos);
	}
	if(property->is_retain_available){
		assert(command == CONNACK);
		packet__write_variable(packet, MQTT5_P_RETAIN_AVAILABLE);
		packet__write_byte(packet, property->retain_available);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: RETAIN_AVAILABLE = %d", property->retain_available);
	}
	if(property->user_propertys_count > 0){
		assert((command == CONNECT) || (command == CONNACK) || (command == PUBLISH) ||
			   (command == PUBACK) || (command == PUBREC) || (command == PUBREL) ||
			   (command == PUBCOMP) || (command == SUBACK) || (command == UNSUBACK) ||
			   (command == DISCONNECT) || (command == AUTH));
		for(i = 0; i < property->user_propertys_count; i++){
			packet__write_variable(packet, MQTT5_P_USER_PROPERTY);
			assert(property->user_property_keys[i]);
			assert(property->user_property_values[i]);
			packet__write_string(packet, property->user_property_keys[i], strlen(property->user_property_keys[i]));
			log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: USER_PROPERTY = %s", property->user_property_keys[i]);
			packet__write_string(packet, property->user_property_values[i], strlen(property->user_property_values[i]));
			log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: USER_PROPERTY = %s", property->user_property_values[i]);
		}
	}
	if(property->is_maximum_packet_size){
		assert((command == CONNECT) || (command == CONNACK));
		packet__write_variable(packet, MQTT5_P_MAXIMUM_PACKET_SIZE);
		packet__write_bytes(packet, &property->maximum_packet_size, 4);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: MAXIMUM_PACKET_SIZE = %d", property->retain_available);
	}
	if(property->is_wildcard_subscription_available){
		assert(command == CONNACK);
		packet__write_variable(packet, MQTT5_P_WILDCARD_SUBSCRIPTION_AVAILABLE);
		packet__write_byte(packet, property->wildcard_subscription_available);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: WILDCARD_SUBSCRIPTION_AVAILABLE = %d", property->wildcard_subscription_available);
	}
	if(property->is_subscription_identifier_available){
		assert(command == CONNACK);
		packet__write_variable(packet, MQTT5_P_SUBSCRIPTION_IDENTIFIER_AVAILABLE);
		packet__write_byte(packet, property->subscription_identifier_available);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: SUBSCRIPTION_IDENTIFIER_AVAILABLE = %d", property->subscription_identifier_available);
	}
	if(property->is_shared_subscription_available){
		assert(command == CONNACK);
		packet__write_variable(packet, MQTT5_P_SHARED_SUBSCRIPTION_AVAILABLE);
		packet__write_byte(packet, property->shared_subscription_available);
		log__printf(mosq, MOSQ_LOG_DEBUG, "Write v5 property: SHARED_SUBSCRIPTION_AVAILABLE = %d", property->shared_subscription_available);
	}

	assert(packet->pos == start_pos + len);
}

void packet__property_content_free(struct mosquitto_v5_property *property)
{
	int i;
	if(!property) return;
	mosquitto__free(property->content_type);
	mosquitto__free(property->response_topic);
	mosquitto__free(property->correlation_data);
	mosquitto__free(property->subscription_identifiers);
	mosquitto__free(property->assigned_client_identifier);
	mosquitto__free(property->authentication_method);
	mosquitto__free(property->authentication_data);
	mosquitto__free(property->response_information);
	mosquitto__free(property->server_reference);
	mosquitto__free(property->reason_string);
	for(i = 0; i < property->user_propertys_count; i++){
		mosquitto__free(property->user_property_keys[i]);
		mosquitto__free(property->user_property_values[i]);
	}
	mosquitto__free(property->user_property_keys);
	mosquitto__free(property->user_property_values);
	memset(property, 0, sizeof(struct mosquitto_v5_property));
}

// Convert payloads between v3 and v5
// NOTE: Mosquitto maintains PUBLISH message's v5 property in a part of its payload.
int packet__payload_convert(struct mosquitto *mosq, uint8_t src_version, uint8_t dst_version, uint32_t src_payloadlen, const void *src_payload, uint32_t *dst_payloadlen, void **dst_payload)
{
	int rc = 0;
	struct mosquitto__packet *packet = NULL;
	varint_t propertylen = 0;
	int start_pos, propertylen_withlen;

	assert(*dst_payloadlen == 0);
	assert(*dst_payload == NULL);

	if((src_version != dst_version) && ((src_version == PROTOCOL_VERSION_v5) || (dst_version == PROTOCOL_VERSION_v5))){
		log__printf(mosq, MOSQ_LOG_DEBUG, "Converting messages from version %d to version %d.", src_version, dst_version);
		if(dst_version == PROTOCOL_VERSION_v5){
			// v3.x -> v5, Add zero length property
			*dst_payloadlen = src_payloadlen + 1;
			*dst_payload = mosquitto__calloc(1, *dst_payloadlen);
			if(!dst_payload) return MOSQ_ERR_NOMEM;
			memcpy(((uint8_t*)*dst_payload) + 1, src_payload, src_payloadlen);
		}else{
			// v5 -> v3.x, Delete property
			packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
			if(!packet) return MOSQ_ERR_NOMEM;
			packet->command = PUBLISH;
			packet->remaining_length = src_payloadlen;
			rc = packet__alloc(packet);
			if(rc){
				mosquitto__free(packet);
				return rc;
			}
			start_pos = packet->pos;
			packet__write_bytes(packet, src_payload, src_payloadlen);
			packet->pos = start_pos;
			rc = packet__read_variable(packet, &propertylen);
			packet__cleanup(packet);
			mosquitto__free(packet);
			if(rc) return rc;
			propertylen_withlen = variable_len(propertylen) + propertylen;
			packet->pos += propertylen_withlen;

			if(propertylen_withlen > src_payloadlen){
				rc = MOSQ_ERR_PROTOCOL;
			}else if(propertylen_withlen == src_payloadlen){
				rc = MOSQ_ERR_SUCCESS;
			}else{
				*dst_payloadlen = src_payloadlen - propertylen_withlen;
				*dst_payload = mosquitto__calloc(1, *dst_payloadlen);
				if(!(*dst_payload)){
					return MOSQ_ERR_NOMEM;
				}
				memcpy(*dst_payload, ((uint8_t*)src_payload) + propertylen_withlen, *dst_payloadlen);
				rc = MOSQ_ERR_SUCCESS;
			}
			return rc;
		}
	}else{
		*dst_payloadlen = src_payloadlen;
		*dst_payload = mosquitto__calloc(1, *dst_payloadlen);
		if(!dst_payload) return MOSQ_ERR_NOMEM;
		memcpy(*dst_payload, src_payload, src_payloadlen);
	}
	return MOSQ_ERR_SUCCESS;
}

int packet__write(struct mosquitto *mosq)
{
	ssize_t write_length;
	struct mosquitto__packet *packet;

	if(!mosq) return MOSQ_ERR_INVAL;
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;

	pthread_mutex_lock(&mosq->current_out_packet_mutex);
	pthread_mutex_lock(&mosq->out_packet_mutex);
	if(mosq->out_packet && !mosq->current_out_packet){
		mosq->current_out_packet = mosq->out_packet;
		mosq->out_packet = mosq->out_packet->next;
		if(!mosq->out_packet){
			mosq->out_packet_last = NULL;
		}
	}
	pthread_mutex_unlock(&mosq->out_packet_mutex);

	if(mosq->state == mosq_cs_connect_pending){
		pthread_mutex_unlock(&mosq->current_out_packet_mutex);
		return MOSQ_ERR_SUCCESS;
	}

	while(mosq->current_out_packet){
		packet = mosq->current_out_packet;

		while(packet->to_process > 0){
			write_length = net__write(mosq, &(packet->payload[packet->pos]), packet->to_process);
			if(write_length > 0){
				G_BYTES_SENT_INC(write_length);
				packet->to_process -= write_length;
				packet->pos += write_length;
			}else{
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
					pthread_mutex_unlock(&mosq->current_out_packet_mutex);
					return MOSQ_ERR_SUCCESS;
				}else{
					pthread_mutex_unlock(&mosq->current_out_packet_mutex);
					switch(errno){
						case COMPAT_ECONNRESET:
							return MOSQ_ERR_CONN_LOST;
						default:
							return MOSQ_ERR_ERRNO;
					}
				}
			}
		}

		G_MSGS_SENT_INC(1);
		if(((packet->command)&0xF6) == PUBLISH){
			G_PUB_MSGS_SENT_INC(1);
#ifndef WITH_BROKER
			pthread_mutex_lock(&mosq->callback_mutex);
			if(mosq->on_publish){
				/* This is a QoS=0 message */
				mosq->in_callback = true;
				mosq->on_publish(mosq, mosq->userdata, packet->mid);
				mosq->in_callback = false;
			}
			pthread_mutex_unlock(&mosq->callback_mutex);
		}else if(((packet->command)&0xF0) == DISCONNECT){
			/* FIXME what cleanup needs doing here? 
			 * incoming/outgoing messages? */
			net__socket_close(mosq);

			/* Start of duplicate, possibly unnecessary code.
			 * This does leave things in a consistent state at least. */
			/* Free data and reset values */
			pthread_mutex_lock(&mosq->out_packet_mutex);
			mosq->current_out_packet = mosq->out_packet;
			if(mosq->out_packet){
				mosq->out_packet = mosq->out_packet->next;
				if(!mosq->out_packet){
					mosq->out_packet_last = NULL;
				}
			}
			pthread_mutex_unlock(&mosq->out_packet_mutex);

			packet__cleanup(packet);
			mosquitto__free(packet);

			pthread_mutex_lock(&mosq->msgtime_mutex);
			mosq->next_msg_out = mosquitto_time() + mosq->keepalive;
			pthread_mutex_unlock(&mosq->msgtime_mutex);
			/* End of duplicate, possibly unnecessary code */

			pthread_mutex_lock(&mosq->callback_mutex);
			if(mosq->on_disconnect){
				mosq->in_callback = true;
				mosq->on_disconnect(mosq, mosq->userdata, 0);
				mosq->in_callback = false;
			}
			pthread_mutex_unlock(&mosq->callback_mutex);
			pthread_mutex_unlock(&mosq->current_out_packet_mutex);
			return MOSQ_ERR_SUCCESS;
#endif
		}

		/* Free data and reset values */
		pthread_mutex_lock(&mosq->out_packet_mutex);
		mosq->current_out_packet = mosq->out_packet;
		if(mosq->out_packet){
			mosq->out_packet = mosq->out_packet->next;
			if(!mosq->out_packet){
				mosq->out_packet_last = NULL;
			}
		}
		pthread_mutex_unlock(&mosq->out_packet_mutex);

		packet__cleanup(packet);
		mosquitto__free(packet);

		pthread_mutex_lock(&mosq->msgtime_mutex);
		mosq->next_msg_out = mosquitto_time() + mosq->keepalive;
		pthread_mutex_unlock(&mosq->msgtime_mutex);
	}
	pthread_mutex_unlock(&mosq->current_out_packet_mutex);
	return MOSQ_ERR_SUCCESS;
}


#ifdef WITH_BROKER
int packet__read(struct mosquitto_db *db, struct mosquitto *mosq)
#else
int packet__read(struct mosquitto *mosq)
#endif
{
	uint8_t byte;
	ssize_t read_length;
	int rc = 0;

	if(!mosq) return MOSQ_ERR_INVAL;
	if(mosq->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;
	if(mosq->state == mosq_cs_connect_pending){
		return MOSQ_ERR_SUCCESS;
	}

	/* This gets called if pselect() indicates that there is network data
	 * available - ie. at least one byte.  What we do depends on what data we
	 * already have.
	 * If we've not got a command, attempt to read one and save it. This should
	 * always work because it's only a single byte.
	 * Then try to read the remaining length. This may fail because it is may
	 * be more than one byte - will need to save data pending next read if it
	 * does fail.
	 * Then try to read the remaining payload, where 'payload' here means the
	 * combined variable header and actual payload. This is the most likely to
	 * fail due to longer length, so save current data and current position.
	 * After all data is read, send to mosquitto__handle_packet() to deal with.
	 * Finally, free the memory and reset everything to starting conditions.
	 */
	if(!mosq->in_packet.command){
		read_length = net__read(mosq, &byte, 1);
		if(read_length == 1){
			mosq->in_packet.command = byte;
#ifdef WITH_BROKER
			G_BYTES_RECEIVED_INC(1);
			/* Clients must send CONNECT as their first command. */
			if(!(mosq->bridge) && mosq->state == mosq_cs_new && (byte&0xF0) != CONNECT) return MOSQ_ERR_PROTOCOL;
#endif
		}else{
			if(read_length == 0) return MOSQ_ERR_CONN_LOST; /* EOF */
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
				return MOSQ_ERR_SUCCESS;
			}else{
				switch(errno){
					case COMPAT_ECONNRESET:
						return MOSQ_ERR_CONN_LOST;
					default:
						return MOSQ_ERR_ERRNO;
				}
			}
		}
	}
	/* remaining_count is the number of bytes that the remaining_length
	 * parameter occupied in this incoming packet. We don't use it here as such
	 * (it is used when allocating an outgoing packet), but we must be able to
	 * determine whether all of the remaining_length parameter has been read.
	 * remaining_count has three states here:
	 *   0 means that we haven't read any remaining_length bytes
	 *   <0 means we have read some remaining_length bytes but haven't finished
	 *   >0 means we have finished reading the remaining_length bytes.
	 */
	if(mosq->in_packet.remaining_count <= 0){
		do{
			read_length = net__read(mosq, &byte, 1);
			if(read_length == 1){
				mosq->in_packet.remaining_count--;
				/* Max 4 bytes length for remaining length as defined by protocol.
				 * Anything more likely means a broken/malicious client.
				 */
				if(mosq->in_packet.remaining_count < -4) return MOSQ_ERR_PROTOCOL;

				G_BYTES_RECEIVED_INC(1);
				mosq->in_packet.remaining_length += (byte & 127) * mosq->in_packet.remaining_mult;
				mosq->in_packet.remaining_mult *= 128;
			}else{
				if(read_length == 0) return MOSQ_ERR_CONN_LOST; /* EOF */
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
					return MOSQ_ERR_SUCCESS;
				}else{
					switch(errno){
						case COMPAT_ECONNRESET:
							return MOSQ_ERR_CONN_LOST;
						default:
							return MOSQ_ERR_ERRNO;
					}
				}
			}
		}while((byte & 128) != 0);
		/* We have finished reading remaining_length, so make remaining_count
		 * positive. */
		mosq->in_packet.remaining_count *= -1;

		if(mosq->in_packet.remaining_length > 0){
			mosq->in_packet.payload = mosquitto__malloc(mosq->in_packet.remaining_length*sizeof(uint8_t));
			if(!mosq->in_packet.payload) return MOSQ_ERR_NOMEM;
			mosq->in_packet.to_process = mosq->in_packet.remaining_length;
		}
	}
	while(mosq->in_packet.to_process>0){
		read_length = net__read(mosq, &(mosq->in_packet.payload[mosq->in_packet.pos]), mosq->in_packet.to_process);
		if(read_length > 0){
			G_BYTES_RECEIVED_INC(read_length);
			mosq->in_packet.to_process -= read_length;
			mosq->in_packet.pos += read_length;
		}else{
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
				if(mosq->in_packet.to_process > 1000){
					/* Update last_msg_in time if more than 1000 bytes left to
					 * receive. Helps when receiving large messages.
					 * This is an arbitrary limit, but with some consideration.
					 * If a client can't send 1000 bytes in a second it
					 * probably shouldn't be using a 1 second keep alive. */
					pthread_mutex_lock(&mosq->msgtime_mutex);
					mosq->last_msg_in = mosquitto_time();
					pthread_mutex_unlock(&mosq->msgtime_mutex);
				}
				return MOSQ_ERR_SUCCESS;
			}else{
				switch(errno){
					case COMPAT_ECONNRESET:
						return MOSQ_ERR_CONN_LOST;
					default:
						return MOSQ_ERR_ERRNO;
				}
			}
		}
	}

	/* All data for this packet is read. */
	mosq->in_packet.pos = 0;
#ifdef WITH_BROKER
	G_MSGS_RECEIVED_INC(1);
	if(((mosq->in_packet.command)&0xF5) == PUBLISH){
		G_PUB_MSGS_RECEIVED_INC(1);
	}
	rc = handle__packet(db, mosq);
#else
	rc = handle__packet(mosq);
#endif

	/* Free data and reset values */
	packet__cleanup(&mosq->in_packet);

	pthread_mutex_lock(&mosq->msgtime_mutex);
	mosq->last_msg_in = mosquitto_time();
	pthread_mutex_unlock(&mosq->msgtime_mutex);
	return rc;
}


