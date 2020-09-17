/*
Copyright (c) 2010-2019 Roger Light <roger@atchoo.org>

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

#ifndef MOSQUITTOPP_H
#define MOSQUITTOPP_H

#if defined(_WIN32) && !defined(LIBMOSQUITTO_STATIC)
#	ifdef mosquittopp_EXPORTS
#		define mosqpp_EXPORT  __declspec(dllexport)
#	else
#		define mosqpp_EXPORT  __declspec(dllimport)
#	endif
#else
#	define mosqpp_EXPORT
#endif

#if defined(__GNUC__) || defined(__clang__)
#  define DEPRECATED __attribute__ ((deprecated))
#else
#  define DEPRECATED
#endif

#include <cstdlib>
#include <mosquitto.h>
#include <time.h>

namespace mosqpp {


mosqpp_EXPORT const char * DEPRECATED strerror(int mosq_errno);
mosqpp_EXPORT const char * DEPRECATED connack_string(int connack_code);
mosqpp_EXPORT int DEPRECATED sub_topic_tokenise(const char *subtopic, char ***topics, int *count);
mosqpp_EXPORT int DEPRECATED sub_topic_tokens_free(char ***topics, int count);
mosqpp_EXPORT int DEPRECATED lib_version(int *major, int *minor, int *revision);
mosqpp_EXPORT int DEPRECATED lib_init();
mosqpp_EXPORT int DEPRECATED lib_cleanup();
mosqpp_EXPORT int DEPRECATED topic_matches_sub(const char *sub, const char *topic, bool *result);
mosqpp_EXPORT int DEPRECATED validate_utf8(const char *str, int len);
mosqpp_EXPORT int DEPRECATED subscribe_simple(
		struct mosquitto_message **messages,
		int msg_count,
		bool retained,
		const char *topic,
		int qos=0,
		const char *host="localhost",
		int port=1883,
		const char *client_id=NULL,
		int keepalive=60,
		bool clean_session=true,
		const char *username=NULL,
		const char *password=NULL,
		const struct libmosquitto_will *will=NULL,
		const struct libmosquitto_tls *tls=NULL);

mosqpp_EXPORT int DEPRECATED subscribe_callback(
		int (*callback)(struct mosquitto *, void *, const struct mosquitto_message *),
		void *userdata,
		const char *topic,
		int qos=0,
		bool retained=true,
		const char *host="localhost",
		int port=1883,
		const char *client_id=NULL,
		int keepalive=60,
		bool clean_session=true,
		const char *username=NULL,
		const char *password=NULL,
		const struct libmosquitto_will *will=NULL,
		const struct libmosquitto_tls *tls=NULL);

/*
 * Class: mosquittopp
 *
 * A mosquitto client class. This is a C++ wrapper class for the mosquitto C
 * library. Please see mosquitto.h for details of the functions.
 */
class mosqpp_EXPORT DEPRECATED mosquittopp {
	private:
		struct mosquitto *m_mosq;
	public:
		DEPRECATED mosquittopp(const char *id=NULL, bool clean_session=true);
		virtual ~mosquittopp();

		int DEPRECATED reinitialise(const char *id, bool clean_session);
		int DEPRECATED socket();
		int DEPRECATED will_set(const char *topic, int payloadlen=0, const void *payload=NULL, int qos=0, bool retain=false);
		int DEPRECATED will_clear();
		int DEPRECATED username_pw_set(const char *username, const char *password=NULL);
		int DEPRECATED connect(const char *host, int port=1883, int keepalive=60);
		int DEPRECATED connect_async(const char *host, int port=1883, int keepalive=60);
		int DEPRECATED connect(const char *host, int port, int keepalive, const char *bind_address);
		int DEPRECATED connect_async(const char *host, int port, int keepalive, const char *bind_address);
		int DEPRECATED reconnect();
		int DEPRECATED reconnect_async();
		int DEPRECATED disconnect();
		int DEPRECATED publish(int *mid, const char *topic, int payloadlen=0, const void *payload=NULL, int qos=0, bool retain=false);
		int DEPRECATED publish_bufs(int *mid, const char *topic, const struct buf *buffers=NULL, int buffers_cnt=0, int qos=0, bool retain=false);
		int DEPRECATED subscribe(int *mid, const char *sub, int qos=0);
		int DEPRECATED unsubscribe(int *mid, const char *sub);
		void DEPRECATED reconnect_delay_set(unsigned int reconnect_delay, unsigned int reconnect_delay_max, bool reconnect_exponential_backoff);
		int DEPRECATED max_inflight_messages_set(unsigned int max_inflight_messages);
		void DEPRECATED message_retry_set(unsigned int message_retry);
		void DEPRECATED user_data_set(void *userdata);
		int DEPRECATED tls_set(const char *cafile, const char *capath=NULL, const char *certfile=NULL, const char *keyfile=NULL, int (*pw_callback)(char *buf, int size, int rwflag, void *userdata)=NULL);
		int DEPRECATED tls_opts_set(int cert_reqs, const char *tls_version=NULL, const char *ciphers=NULL);
		int DEPRECATED tls_insecure_set(bool value);
		int DEPRECATED tls_psk_set(const char *psk, const char *identity, const char *ciphers=NULL);
		int DEPRECATED opts_set(enum mosq_opt_t option, void *value);

		int DEPRECATED loop(int timeout=-1, int max_packets=1);
		int DEPRECATED loop_misc();
		int DEPRECATED loop_read(int max_packets=1);
		int DEPRECATED loop_write(int max_packets=1);
		int DEPRECATED loop_forever(int timeout=-1, int max_packets=1);
		int DEPRECATED loop_start();
		int DEPRECATED loop_stop(bool force=false);
		bool DEPRECATED want_write();
		int DEPRECATED threaded_set(bool threaded=true);
		int DEPRECATED socks5_set(const char *host, int port=1080, const char *username=NULL, const char *password=NULL);

		// names in the functions commented to prevent unused parameter warning
		virtual void on_connect(int /*rc*/) {return;}
		virtual void on_connect_with_flags(int /*rc*/, int /*flags*/) {return;}
		virtual void on_disconnect(int /*rc*/) {return;}
		virtual void on_publish(int /*mid*/) {return;}
		virtual void on_message(const struct mosquitto_message * /*message*/) {return;}
		virtual void on_subscribe(int /*mid*/, int /*qos_count*/, const int * /*granted_qos*/) {return;}
		virtual void on_unsubscribe(int /*mid*/) {return;}
		virtual void on_log(int /*level*/, const char * /*str*/) {return;}
		virtual void on_error() {return;}
};

}
#endif
