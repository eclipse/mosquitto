#pragma once

#include <gmock/gmock.h>
#include <mosquitto_internal.h>

#include "c_function_mock.hpp"

class LibMosquittoMock : public CFunctionMock<LibMosquittoMock> {
	public:
		LibMosquittoMock();
		virtual ~LibMosquittoMock();

		/* libmosquitto.c */
		MOCK_METHOD(int, mosquitto_lib_version, (int *major, int *minor, int *revision));
		MOCK_METHOD(int, mosquitto_lib_init, ());
		MOCK_METHOD(int, mosquitto_lib_cleanup, ());
		MOCK_METHOD(struct mosquitto *, mosquitto_new, (const char *id, bool clean_start, void *userdata));
		MOCK_METHOD(int, mosquitto_reinitialise, (struct mosquitto *mosq, const char *id, bool clean_start,
			void *userdata));
		MOCK_METHOD(void, mosquitto_destroy, (struct mosquitto *mosq));
		MOCK_METHOD(int, mosquitto_socket, (struct mosquitto *mosq));
		MOCK_METHOD(bool, mosquitto_want_write, (struct mosquitto *mosq));

		/* actions_publish.c */
		MOCK_METHOD(int, mosquitto_publish, (struct mosquitto *mosq, int *mid, const char *topic,
			int payloadlen, const /*void*/char *payload, int qos, bool retain));
		MOCK_METHOD(int, mosquitto_publish_v5, (struct mosquitto *mosq, int *mid, const char *topic,
			int payloadlen, const /*void*/char *payload, int qos, bool retain, const mosquitto_property *properties));

		/* actions_subscribe.c */
		MOCK_METHOD(int, mosquitto_subscribe, (struct mosquitto *mosq, int *mid, const char *sub, int qos));
		MOCK_METHOD(int, mosquitto_subscribe_v5, (struct mosquitto *mosq, int *mid, const char *sub, int qos,
			int options, const mosquitto_property *properties));
		MOCK_METHOD(int, mosquitto_subscribe_multiple, (struct mosquitto *mosq, int *mid, int sub_count,
			char *const *const sub, int qos, int options, const mosquitto_property *properties));

		/* actions_unsubscribe.c */
		MOCK_METHOD(int, mosquitto_unsubscribe, (struct mosquitto *mosq, int *mid, const char *sub));
		MOCK_METHOD(int, mosquitto_unsubscribe_v5, (struct mosquitto *mosq, int *mid, const char *sub,
			const mosquitto_property *properties));
		MOCK_METHOD(int, mosquitto_unsubscribe_multiple, (struct mosquitto *mosq, int *mid, int sub_count,
			char *const *const sub, const mosquitto_property *properties));

		/* callbacks.c */
		MOCK_METHOD(void, mosquitto_connect_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_connect on_connect));
		MOCK_METHOD(void, mosquitto_connect_with_flags_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_connect_with_flags on_connect));
		MOCK_METHOD(void, mosquitto_connect_v5_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_connect_v5 on_connect));
		MOCK_METHOD(void, mosquitto_pre_connect_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_pre_connect on_pre_connect));
		MOCK_METHOD(void, mosquitto_disconnect_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_disconnect on_disconnect));
		MOCK_METHOD(void, mosquitto_disconnect_v5_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_disconnect_v5 on_disconnect));
		MOCK_METHOD(void, mosquitto_publish_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_publish on_publish));
		MOCK_METHOD(void, mosquitto_publish_v5_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_publish_v5 on_publish));
		MOCK_METHOD(void, mosquitto_message_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_message on_message));
		MOCK_METHOD(void, mosquitto_message_v5_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_message_v5 on_message));
		MOCK_METHOD(void, mosquitto_subscribe_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_subscribe on_subscribe));
		MOCK_METHOD(void, mosquitto_subscribe_v5_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_subscribe_v5 on_subscribe));
		MOCK_METHOD(void, mosquitto_unsubscribe_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_unsubscribe on_unsubscribe));
		MOCK_METHOD(void, mosquitto_unsubscribe_v5_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_unsubscribe_v5 on_unsubscribe));
		MOCK_METHOD(void, mosquitto_unsubscribe2_v5_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_unsubscribe2_v5 on_unsubscribe));
		MOCK_METHOD(void, mosquitto_log_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_log on_log));
		MOCK_METHOD(void, mosquitto_ext_auth_callback_set, (struct mosquitto *mosq,
			LIBMOSQ_CB_ext_auth on_ext_auth));

		/* connect.c */
		MOCK_METHOD(int, mosquitto_connect, (struct mosquitto *mosq, const char *host,
			int port, int keepalive));
		MOCK_METHOD(int, mosquitto_connect_bind, (struct mosquitto *mosq, const char *host,
			int port, int keepalive, const char *bind_address));
		MOCK_METHOD(int, mosquitto_connect_bind_v5, (struct mosquitto *mosq, const char *host,
			int port, int keepalive, const char *bind_address, const mosquitto_property *properties));
		MOCK_METHOD(int, mosquitto_connect_async, (struct mosquitto *mosq, const char *host,
			int port, int keepalive));
		MOCK_METHOD(int, mosquitto_connect_bind_async, (struct mosquitto *mosq, const char *host,
			int port, int keepalive, const char *bind_address));
		MOCK_METHOD(int, mosquitto_reconnect_async, (struct mosquitto *mosq));
		MOCK_METHOD(int, mosquitto_reconnect, (struct mosquitto *mosq));
		MOCK_METHOD(int, mosquitto_disconnect, (struct mosquitto *mosq));
		MOCK_METHOD(int, mosquitto_disconnect_v5, (struct mosquitto *mosq, int reason_code,
			const mosquitto_property *properties));

		/* extended_auth.c */
		MOCK_METHOD(int, mosquitto_ext_auth_continue, (struct mosquitto *context,
			const char *auth_method, uint16_t auth_data_len, const void *auth_data,
			const mosquitto_property *input_props));

		/* helpers.c */
		MOCK_METHOD(int, mosquitto_subscribe_simple, (struct mosquitto_message **messages,
			int msg_count, bool want_retained, const char *topic, int qos,
			const char *host, int port, const char *clientid, int keepalive,
			bool clean_session, const char *username, const char *password,
			const struct libmosquitto_will *will, const struct libmosquitto_tls *tls));
		MOCK_METHOD(int, mosquitto_subscribe_callback, (int (*callback)(struct mosquitto *,
			void *, const struct mosquitto_message *), void *userdata,
			const char *topic, int qos, const char *host, int port,
			const char *clientid, int keepalive, bool clean_session,
			const char *username, const char *password, const struct libmosquitto_will *will,
			const struct libmosquitto_tls *tls));

		/* loop.c */
		MOCK_METHOD(int, mosquitto_loop, (struct mosquitto *mosq, int timeout, int max_packets));
		MOCK_METHOD(int, mosquitto_loop_forever, (struct mosquitto *mosq, int timeout, int max_packets));
		MOCK_METHOD(int, mosquitto_loop_misc, (struct mosquitto *mosq));
		MOCK_METHOD(int, mosquitto_loop_read, (struct mosquitto *mosq, int max_packets));
		MOCK_METHOD(int, mosquitto_loop_write, (struct mosquitto *mosq, int max_packets));

		/* messages_mosq.c */
		MOCK_METHOD(int, mosquitto_message_copy, (struct mosquitto_message *dst,
			const struct mosquitto_message *src));
		MOCK_METHOD(void, mosquitto_message_free, (struct mosquitto_message **message));
		MOCK_METHOD(void, mosquitto_message_free_contents, (struct mosquitto_message *message));
		MOCK_METHOD(void, mosquitto_message_retry_set, (struct mosquitto *mosq,
			unsigned int message_retry));
		MOCK_METHOD(int, mosquitto_max_inflight_messages_set, (struct mosquitto *mosq,
			unsigned int max_inflight_messages));

		/* net_mosq.c */
		MOCK_METHOD(void *, mosquitto_ssl_get, (struct mosquitto *mosq));

		/* options.c */
		MOCK_METHOD(int, mosquitto_will_set, (struct mosquitto *mosq, const char *topic,
			int payloadlen, const void *payload, int qos, bool retain));
		MOCK_METHOD(int, mosquitto_will_set_v5, (struct mosquitto *mosq, const char *topic,
			int payloadlen, const void *payload, int qos, bool retain,
			mosquitto_property *properties));
		MOCK_METHOD(int, mosquitto_will_clear, (struct mosquitto *mosq));
		MOCK_METHOD(int, mosquitto_username_pw_set, (struct mosquitto *mosq,
			const char *username, const char *password));
		MOCK_METHOD(int, mosquitto_reconnect_delay_set, (struct mosquitto *mosq,
			unsigned int reconnect_delay, unsigned int reconnect_delay_max,
			bool reconnect_exponential_backoff));
		MOCK_METHOD(int, mosquitto_tls_set, (struct mosquitto *mosq, const char *cafile,
			const char *capath, const char *certfile, const char *keyfile,
			int (*pw_callback)(char *buf, int size, int rwflag, void *userdata)));
		MOCK_METHOD(int, mosquitto_tls_opts_set, (struct mosquitto *mosq, int cert_reqs,
			const char *tls_version, const char *ciphers));
		MOCK_METHOD(int, mosquitto_tls_insecure_set, (struct mosquitto *mosq, bool value));
		MOCK_METHOD(int, mosquitto_string_option, (struct mosquitto *mosq,
			enum mosq_opt_t option, const char *value));
		MOCK_METHOD(int, mosquitto_tls_psk_set, (struct mosquitto *mosq, const char *psk,
			const char *identity, const char *ciphers));
		MOCK_METHOD(int, mosquitto_opts_set, (struct mosquitto *mosq, enum mosq_opt_t option,
			void *value));
		MOCK_METHOD(int, mosquitto_int_option, (struct mosquitto *mosq, enum mosq_opt_t option,
			int value));
		MOCK_METHOD(int, mosquitto_void_option, (struct mosquitto *mosq, enum mosq_opt_t option,
			void *value));
		MOCK_METHOD(void, mosquitto_user_data_set, (struct mosquitto *mosq, void *userdata));
		MOCK_METHOD(void *, mosquitto_userdata, (struct mosquitto *mosq));

		/* socks_mosq.c */
		MOCK_METHOD(int,  mosquitto_socks5_set, (struct mosquitto *mosq, const char *host,
			int port, const char *username, const char *password));

		/* srv_mosq.c */
		MOCK_METHOD(int, mosquitto_connect_srv, (struct mosquitto *mosq, const char *host,
			int keepalive, const char *bind_address));

		/* thread_mosq.c */
		MOCK_METHOD(int, mosquitto_loop_start, (struct mosquitto *mosq));
		MOCK_METHOD(int, mosquitto_loop_stop, (struct mosquitto *mosq, bool force));
		MOCK_METHOD(int, mosquitto_threaded_set, (struct mosquitto *mosq, bool threaded));
};
