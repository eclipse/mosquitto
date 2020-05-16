/*
Copyright (c) 2010-2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <errno.h>
#include <signal.h>
#include <string.h>
#ifndef WIN32
#include <sys/time.h>
#include <strings.h>
#endif

#include "logging_mosq.h"
#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt_protocol.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "will_mosq.h"

static unsigned int init_refcount = 0;

void mosquitto__destroy(struct mosquitto *mosq);

int mosquitto_lib_version(int *major, int *minor, int *revision)
{
	if(major) *major = LIBMOSQUITTO_MAJOR;
	if(minor) *minor = LIBMOSQUITTO_MINOR;
	if(revision) *revision = LIBMOSQUITTO_REVISION;
	return LIBMOSQUITTO_VERSION_NUMBER;
}

int mosquitto_lib_init(void)
{
	int rc;

	if (init_refcount == 0) {
#ifdef WIN32
		srand(GetTickCount64());
#elif _POSIX_TIMERS>0 && defined(_POSIX_MONOTONIC_CLOCK)
		struct timespec tp;

		clock_gettime(CLOCK_MONOTONIC, &tp);
		srand(tp.tv_nsec);
#elif defined(__APPLE__)
		uint64_t ticks;

		ticks = mach_absolute_time();
		srand((unsigned int)ticks);
#else
		struct timeval tv;

		gettimeofday(&tv, NULL);
		srand(tv.tv_sec*1000 + tv.tv_usec/1000);
#endif

		rc = net__init();
		if (rc != MOSQ_ERR_SUCCESS) {
			return rc;
		}
	}

	init_refcount++;
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_lib_cleanup(void)
{
	if (init_refcount == 1) {
		net__cleanup();
	}

	if (init_refcount > 0) {
		--init_refcount;
	}

	return MOSQ_ERR_SUCCESS;
}

struct mosquitto *mosquitto_new(const char *id, bool clean_start, void *userdata)
{
	struct mosquitto *mosq = NULL;
	int rc;

	if(clean_start == false && id == NULL){
		errno = EINVAL;
		return NULL;
	}

#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	mosq = (struct mosquitto *)mosquitto__calloc(1, sizeof(struct mosquitto));
	if(mosq){
		mosq->sock = INVALID_SOCKET;
		if(net__socketpair(&mosq->sockpairR, &mosq->sockpairW)){
			log__printf(mosq, MOSQ_LOG_WARNING,
					"Warning: Unable to open socket pair, outgoing publish commands may be delayed.");
		}
#ifdef WITH_THREADING
		mosq->thread_id = pthread_self();
#endif
		rc = mosquitto_reinitialise(mosq, id, clean_start, userdata);
		if(rc){
			mosquitto_destroy(mosq);
			if(rc == MOSQ_ERR_INVAL){
				errno = EINVAL;
			}else if(rc == MOSQ_ERR_NOMEM){
				errno = ENOMEM;
			}
			return NULL;
		}
	}else{
		errno = ENOMEM;
	}
	return mosq;
}

int mosquitto_reinitialise(struct mosquitto *mosq, const char *id, bool clean_start, void *userdata)
{
	if(!mosq) return MOSQ_ERR_INVAL;

	if(clean_start == false && id == NULL){
		return MOSQ_ERR_INVAL;
	}

	mosquitto__destroy(mosq);
	memset(mosq, 0, sizeof(struct mosquitto));

	if(userdata){
		mosq->userdata = userdata;
	}else{
		mosq->userdata = mosq;
	}
	mosq->protocol = mosq_p_mqtt311;
	mosq->sock = INVALID_SOCKET;
	if(net__socketpair(&mosq->sockpairR, &mosq->sockpairW)){
		log__printf(mosq, MOSQ_LOG_WARNING,
				"Warning: Unable to open socket pair, outgoing publish commands may be delayed.");
	}
	mosq->keepalive = 60;
	mosq->clean_start = clean_start;
	if(id){
		if(STREMPTY(id)){
			return MOSQ_ERR_INVAL;
		}
		if(mosquitto_validate_utf8(id, strlen(id))){
			return MOSQ_ERR_MALFORMED_UTF8;
		}
		mosq->id = mosquitto__strdup(id);
	}
	mosq->in_packet.payload = NULL;
	packet__cleanup(&mosq->in_packet);
	mosq->out_packet = NULL;
	mosq->current_out_packet = NULL;
	mosq->last_msg_in = mosquitto_time();
	mosq->next_msg_out = mosquitto_time() + mosq->keepalive;
	mosq->ping_t = 0;
	mosq->last_mid = 0;
	mosq->state = mosq_cs_new;
	mosq->maximum_qos = 2;
	mosq->msgs_in.inflight_maximum = 20;
	mosq->msgs_out.inflight_maximum = 20;
	mosq->msgs_in.inflight_quota = 20;
	mosq->msgs_out.inflight_quota = 20;
	mosq->will = NULL;
	mosq->on_connect = NULL;
	mosq->on_publish = NULL;
	mosq->on_message = NULL;
	mosq->on_subscribe = NULL;
	mosq->on_unsubscribe = NULL;
	mosq->host = NULL;
	mosq->port = 1883;
	mosq->in_callback = false;
	mosq->reconnect_delay = 1;
	mosq->reconnect_delay_max = 1;
	mosq->reconnect_exponential_backoff = false;
	mosq->threaded = mosq_ts_none;
#ifdef WITH_TLS
	mosq->ssl = NULL;
	mosq->ssl_ctx = NULL;
	mosq->tls_cert_reqs = SSL_VERIFY_PEER;
	mosq->tls_insecure = false;
	mosq->want_write = false;
	mosq->tls_ocsp_required = false;
#endif
#ifdef WITH_THREADING
	pthread_mutex_init(&mosq->callback_mutex, NULL);
	pthread_mutex_init(&mosq->log_callback_mutex, NULL);
	pthread_mutex_init(&mosq->state_mutex, NULL);
	pthread_mutex_init(&mosq->out_packet_mutex, NULL);
	pthread_mutex_init(&mosq->current_out_packet_mutex, NULL);
	pthread_mutex_init(&mosq->msgtime_mutex, NULL);
	pthread_mutex_init(&mosq->msgs_in.mutex, NULL);
	pthread_mutex_init(&mosq->msgs_out.mutex, NULL);
	pthread_mutex_init(&mosq->mid_mutex, NULL);
	mosq->thread_id = pthread_self();
#endif

	return MOSQ_ERR_SUCCESS;
}


void mosquitto__destroy(struct mosquitto *mosq)
{
	struct mosquitto__packet *packet;
	if(!mosq) return;

#ifdef WITH_THREADING
#  ifdef HAVE_PTHREAD_CANCEL
	if(mosq->threaded == mosq_ts_self && !pthread_equal(mosq->thread_id, pthread_self())){
		pthread_cancel(mosq->thread_id);
		pthread_join(mosq->thread_id, NULL);
		mosq->threaded = mosq_ts_none;
	}
#  endif

	if(mosq->id){
		/* If mosq->id is not NULL then the client has already been initialised
		 * and so the mutexes need destroying. If mosq->id is NULL, the mutexes
		 * haven't been initialised. */
		pthread_mutex_destroy(&mosq->callback_mutex);
		pthread_mutex_destroy(&mosq->log_callback_mutex);
		pthread_mutex_destroy(&mosq->state_mutex);
		pthread_mutex_destroy(&mosq->out_packet_mutex);
		pthread_mutex_destroy(&mosq->current_out_packet_mutex);
		pthread_mutex_destroy(&mosq->msgtime_mutex);
		pthread_mutex_destroy(&mosq->msgs_in.mutex);
		pthread_mutex_destroy(&mosq->msgs_out.mutex);
		pthread_mutex_destroy(&mosq->mid_mutex);
	}
#endif
	if(mosq->sock != INVALID_SOCKET){
		net__socket_close(mosq);
	}
	message__cleanup_all(mosq);
	will__clear(mosq);
#ifdef WITH_TLS
	if(mosq->ssl){
		SSL_free(mosq->ssl);
	}
	if(mosq->ssl_ctx){
		SSL_CTX_free(mosq->ssl_ctx);
	}
	mosquitto__free(mosq->tls_cafile);
	mosquitto__free(mosq->tls_capath);
	mosquitto__free(mosq->tls_certfile);
	mosquitto__free(mosq->tls_keyfile);
	if(mosq->tls_pw_callback) mosq->tls_pw_callback = NULL;
	mosquitto__free(mosq->tls_version);
	mosquitto__free(mosq->tls_ciphers);
	mosquitto__free(mosq->tls_psk);
	mosquitto__free(mosq->tls_psk_identity);
	mosquitto__free(mosq->tls_alpn);
#endif

	mosquitto__free(mosq->address);
	mosq->address = NULL;

	mosquitto__free(mosq->id);
	mosq->id = NULL;

	mosquitto__free(mosq->username);
	mosq->username = NULL;

	mosquitto__free(mosq->password);
	mosq->password = NULL;

	mosquitto__free(mosq->host);
	mosq->host = NULL;

	mosquitto__free(mosq->bind_address);
	mosq->bind_address = NULL;

	/* Out packet cleanup */
	if(mosq->out_packet && !mosq->current_out_packet){
		mosq->current_out_packet = mosq->out_packet;
		mosq->out_packet = mosq->out_packet->next;
	}
	while(mosq->current_out_packet){
		packet = mosq->current_out_packet;
		/* Free data and reset values */
		mosq->current_out_packet = mosq->out_packet;
		if(mosq->out_packet){
			mosq->out_packet = mosq->out_packet->next;
		}

		packet__cleanup(packet);
		mosquitto__free(packet);
	}

	packet__cleanup(&mosq->in_packet);
	if(mosq->sockpairR != INVALID_SOCKET){
		COMPAT_CLOSE(mosq->sockpairR);
		mosq->sockpairR = INVALID_SOCKET;
	}
	if(mosq->sockpairW != INVALID_SOCKET){
		COMPAT_CLOSE(mosq->sockpairW);
		mosq->sockpairW = INVALID_SOCKET;
	}
}

void mosquitto_destroy(struct mosquitto *mosq)
{
	if(!mosq) return;

	mosquitto__destroy(mosq);
	mosquitto__free(mosq);
}

int mosquitto_socket(struct mosquitto *mosq)
{
	if(!mosq) return INVALID_SOCKET;
	return mosq->sock;
}


bool mosquitto_want_write(struct mosquitto *mosq)
{
	bool result = false;
	if(mosq->out_packet || mosq->current_out_packet){
		result = true;
	}
#ifdef WITH_TLS
	if(mosq->ssl){
		if (mosq->want_write) {
			result = true;
		}else if(mosq->want_connect){
			result = false;
		}
	}
#endif
	return result;
}


const char *mosquitto_strerror(int mosq_errno)
{
	switch(mosq_errno){
		case MOSQ_ERR_AUTH_CONTINUE:
			return "Continue with authentication.";
		case MOSQ_ERR_NO_SUBSCRIBERS:
			return "No subscribers.";
		case MOSQ_ERR_SUB_EXISTS:
			return "Subscription already exists.";
		case MOSQ_ERR_CONN_PENDING:
			return "Connection pending.";
		case MOSQ_ERR_SUCCESS:
			return "No error.";
		case MOSQ_ERR_NOMEM:
			return "Out of memory.";
		case MOSQ_ERR_PROTOCOL:
			return "A network protocol error occurred when communicating with the broker.";
		case MOSQ_ERR_INVAL:
			return "Invalid function arguments provided.";
		case MOSQ_ERR_NO_CONN:
			return "The client is not currently connected.";
		case MOSQ_ERR_CONN_REFUSED:
			return "The connection was refused.";
		case MOSQ_ERR_NOT_FOUND:
			return "Message not found (internal error).";
		case MOSQ_ERR_CONN_LOST:
			return "The connection was lost.";
		case MOSQ_ERR_TLS:
			return "A TLS error occurred.";
		case MOSQ_ERR_PAYLOAD_SIZE:
			return "Payload too large.";
		case MOSQ_ERR_NOT_SUPPORTED:
			return "This feature is not supported.";
		case MOSQ_ERR_AUTH:
			return "Authorisation failed.";
		case MOSQ_ERR_ACL_DENIED:
			return "Access denied by ACL.";
		case MOSQ_ERR_UNKNOWN:
			return "Unknown error.";
		case MOSQ_ERR_ERRNO:
			return strerror(errno);
		case MOSQ_ERR_EAI:
			return "Lookup error.";
		case MOSQ_ERR_PROXY:
			return "Proxy error.";
		case MOSQ_ERR_MALFORMED_UTF8:
			return "Malformed UTF-8";
		case MOSQ_ERR_DUPLICATE_PROPERTY:
			return "Duplicate property in property list";
		case MOSQ_ERR_TLS_HANDSHAKE:
			return "TLS handshake failed.";
		case MOSQ_ERR_QOS_NOT_SUPPORTED:
			return "Requested QoS not supported on server.";
		case MOSQ_ERR_OVERSIZE_PACKET:
			return "Packet larger than supported by the server.";
		case MOSQ_ERR_OCSP:
			return "OCSP error.";
		default:
			return "Unknown error.";
	}
}

const char *mosquitto_connack_string(int connack_code)
{
	switch(connack_code){
		case 0:
			return "Connection Accepted.";
		case 1:
			return "Connection Refused: unacceptable protocol version.";
		case 2:
			return "Connection Refused: identifier rejected.";
		case 3:
			return "Connection Refused: broker unavailable.";
		case 4:
			return "Connection Refused: bad user name or password.";
		case 5:
			return "Connection Refused: not authorised.";
		default:
			return "Connection Refused: unknown reason.";
	}
}

const char *mosquitto_reason_string(int reason_code)
{
	switch(reason_code){
		case MQTT_RC_SUCCESS:
			return "Success";
		case MQTT_RC_GRANTED_QOS1:
			return "Granted QoS 1";
		case MQTT_RC_GRANTED_QOS2:
			return "Granted QoS 2";
		case MQTT_RC_DISCONNECT_WITH_WILL_MSG:
			return "Disconnect with Will Message";
		case MQTT_RC_NO_MATCHING_SUBSCRIBERS:
			return "No matching subscribers";
		case MQTT_RC_NO_SUBSCRIPTION_EXISTED:
			return "No subscription existed";
		case MQTT_RC_CONTINUE_AUTHENTICATION:
			return "Continue authentication";
		case MQTT_RC_REAUTHENTICATE:
			return "Re-authenticate";

		case MQTT_RC_UNSPECIFIED:
			return "Unspecified error";
		case MQTT_RC_MALFORMED_PACKET:
			return "Malformed Packet";
		case MQTT_RC_PROTOCOL_ERROR:
			return "Protocol Error";
		case MQTT_RC_IMPLEMENTATION_SPECIFIC:
			return "Implementation specific error";
		case MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION:
			return "Unsupported Protocol Version";
		case MQTT_RC_CLIENTID_NOT_VALID:
			return "Client Identifier not valid";
		case MQTT_RC_BAD_USERNAME_OR_PASSWORD:
			return "Bad User Name or Password";
		case MQTT_RC_NOT_AUTHORIZED:
			return "Not authorized";
		case MQTT_RC_SERVER_UNAVAILABLE:
			return "Server unavailable";
		case MQTT_RC_SERVER_BUSY:
			return "Server busy";
		case MQTT_RC_BANNED:
			return "Banned";
		case MQTT_RC_SERVER_SHUTTING_DOWN:
			return "Server shutting down";
		case MQTT_RC_BAD_AUTHENTICATION_METHOD:
			return "Bad authentication method";
		case MQTT_RC_KEEP_ALIVE_TIMEOUT:
			return "Keep Alive timeout";
		case MQTT_RC_SESSION_TAKEN_OVER:
			return "Session taken over";
		case MQTT_RC_TOPIC_FILTER_INVALID:
			return "Topic Filter invalid";
		case MQTT_RC_TOPIC_NAME_INVALID:
			return "Topic Name invalid";
		case MQTT_RC_PACKET_ID_IN_USE:
			return "Packet Identifier in use";
		case MQTT_RC_PACKET_ID_NOT_FOUND:
			return "Packet Identifier not found";
		case MQTT_RC_RECEIVE_MAXIMUM_EXCEEDED:
			return "Receive Maximum exceeded";
		case MQTT_RC_TOPIC_ALIAS_INVALID:
			return "Topic Alias invalid";
		case MQTT_RC_PACKET_TOO_LARGE:
			return "Packet too large";
		case MQTT_RC_MESSAGE_RATE_TOO_HIGH:
			return "Message rate too high";
		case MQTT_RC_QUOTA_EXCEEDED:
			return "Quota exceeded";
		case MQTT_RC_ADMINISTRATIVE_ACTION:
			return "Administrative action";
		case MQTT_RC_PAYLOAD_FORMAT_INVALID:
			return "Payload format invalid";
		case MQTT_RC_RETAIN_NOT_SUPPORTED:
			return "Retain not supported";
		case MQTT_RC_QOS_NOT_SUPPORTED:
			return "QoS not supported";
		case MQTT_RC_USE_ANOTHER_SERVER:
			return "Use another server";
		case MQTT_RC_SERVER_MOVED:
			return "Server moved";
		case MQTT_RC_SHARED_SUBS_NOT_SUPPORTED:
			return "Shared Subscriptions not supported";
		case MQTT_RC_CONNECTION_RATE_EXCEEDED:
			return "Connection rate exceeded";
		case MQTT_RC_MAXIMUM_CONNECT_TIME:
			return "Maximum connect time";
		case MQTT_RC_SUBSCRIPTION_IDS_NOT_SUPPORTED:
			return "Subscription identifiers not supported";
		case MQTT_RC_WILDCARD_SUBS_NOT_SUPPORTED:
			return "Wildcard Subscriptions not supported";
		default:
			return "Unknown reason";
	}
}


int mosquitto_string_to_command(const char *str, int *cmd)
{
	if(!strcasecmp(str, "connect")){
		*cmd = CMD_CONNECT;
	}else if(!strcasecmp(str, "connack")){
		*cmd = CMD_CONNACK;
	}else if(!strcasecmp(str, "publish")){
		*cmd = CMD_PUBLISH;
	}else if(!strcasecmp(str, "puback")){
		*cmd = CMD_PUBACK;
	}else if(!strcasecmp(str, "pubrec")){
		*cmd = CMD_PUBREC;
	}else if(!strcasecmp(str, "pubrel")){
		*cmd = CMD_PUBREL;
	}else if(!strcasecmp(str, "pubcomp")){
		*cmd = CMD_PUBCOMP;
	}else if(!strcasecmp(str, "subscribe")){
		*cmd = CMD_SUBSCRIBE;
	}else if(!strcasecmp(str, "unsubscribe")){
		*cmd = CMD_UNSUBSCRIBE;
	}else if(!strcasecmp(str, "disconnect")){
		*cmd = CMD_DISCONNECT;
	}else if(!strcasecmp(str, "auth")){
		*cmd = CMD_AUTH;
	}else if(!strcasecmp(str, "will")){
		*cmd = CMD_WILL;
	}else{
		return MOSQ_ERR_INVAL;
	}
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_sub_topic_tokenise(const char *subtopic, char ***topics, int *count)
{
	int len;
	int hier_count = 1;
	int start, stop;
	int hier;
	int tlen;
	int i, j;

	if(!subtopic || !topics || !count) return MOSQ_ERR_INVAL;

	len = strlen(subtopic);

	for(i=0; i<len; i++){
		if(subtopic[i] == '/'){
			if(i > len-1){
				/* Separator at end of line */
			}else{
				hier_count++;
			}
		}
	}

	(*topics) = mosquitto__calloc(hier_count, sizeof(char *));
	if(!(*topics)) return MOSQ_ERR_NOMEM;

	start = 0;
	hier = 0;

	for(i=0; i<len+1; i++){
		if(subtopic[i] == '/' || subtopic[i] == '\0'){
			stop = i;
			if(start != stop){
				tlen = stop-start + 1;
				(*topics)[hier] = mosquitto__calloc(tlen, sizeof(char));
				if(!(*topics)[hier]){
					for(j=0; j<hier; j++){
						mosquitto__free((*topics)[j]);
					}
					mosquitto__free((*topics));
					return MOSQ_ERR_NOMEM;
				}
				for(j=start; j<stop; j++){
					(*topics)[hier][j-start] = subtopic[j];
				}
			}
			start = i+1;
			hier++;
		}
	}

	*count = hier_count;

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_sub_topic_tokens_free(char ***topics, int count)
{
	int i;

	if(!topics || !(*topics) || count<1) return MOSQ_ERR_INVAL;

	for(i=0; i<count; i++){
		mosquitto__free((*topics)[i]);
	}
	mosquitto__free(*topics);

	return MOSQ_ERR_SUCCESS;
}

