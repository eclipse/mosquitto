/*
Copyright (c) 2010-2019 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
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

#include <cstdlib>
#include <mosquitto.h>
#include <time.h>

namespace mosqpp {


mosqpp_EXPORT const char * strerror(int mosq_errno);
mosqpp_EXPORT const char * connack_string(int connack_code);
mosqpp_EXPORT int sub_topic_tokenise(const char *subtopic, char ***topics, int *count);
mosqpp_EXPORT int sub_topic_tokens_free(char ***topics, int count);
mosqpp_EXPORT int lib_version(int *major, int *minor, int *revision);
mosqpp_EXPORT int lib_init();
mosqpp_EXPORT int lib_cleanup();
mosqpp_EXPORT int topic_matches_sub(const char *sub, const char *topic, bool *result);
mosqpp_EXPORT int validate_utf8(const char *str, int len);
mosqpp_EXPORT int subscribe_simple(
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

mosqpp_EXPORT int subscribe_callback(
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
class mosqpp_EXPORT mosquittopp {
	private:
		struct mosquitto *m_mosq;
	public:
		mosquittopp(const char *id=NULL, bool clean_session=true);
		virtual ~mosquittopp();

		int reinitialise(const char *id, bool clean_session);
		int socket();
		int will_set(const char *topic, int payloadlen=0, const void *payload=NULL, int qos=0, bool retain=false);
		int will_clear();
		int username_pw_set(const char *username, const char *password=NULL);
		int connect(const char *host, int port=1883, int keepalive=60);
		int connect_async(const char *host, int port=1883, int keepalive=60);
		int connect(const char *host, int port, int keepalive, const char *bind_address);
		int connect_async(const char *host, int port, int keepalive, const char *bind_address);
		int reconnect();
		int reconnect_async();
		int disconnect();
		int publish(int *mid, const char *topic, int payloadlen=0, const void *payload=NULL, int qos=0, bool retain=false);
		int subscribe(int *mid, const char *sub, int qos=0);
		int unsubscribe(int *mid, const char *sub);
		void reconnect_delay_set(unsigned int reconnect_delay, unsigned int reconnect_delay_max, bool reconnect_exponential_backoff);
		int max_inflight_messages_set(unsigned int max_inflight_messages);
		void message_retry_set(unsigned int message_retry);
		void user_data_set(void *userdata);
		int tls_set(const char *cafile, const char *capath=NULL, const char *certfile=NULL, const char *keyfile=NULL, int (*pw_callback)(char *buf, int size, int rwflag, void *userdata)=NULL);
		int tls_opts_set(int cert_reqs, const char *tls_version=NULL, const char *ciphers=NULL);
		int tls_insecure_set(bool value);
		int tls_psk_set(const char *psk, const char *identity, const char *ciphers=NULL);
		int opts_set(enum mosq_opt_t option, void *value);

		int loop(int timeout=-1, int max_packets=1);
		int loop_misc();
		int loop_read(int max_packets=1);
		int loop_write(int max_packets=1);
		int loop_forever(int timeout=-1, int max_packets=1);
		int loop_start();
		int loop_stop(bool force=false);
		bool want_write();
		int threaded_set(bool threaded=true);
		int socks5_set(const char *host, int port=1080, const char *username=NULL, const char *password=NULL);

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
