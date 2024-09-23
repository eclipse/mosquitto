R=..
include ${R}/config.mk

.PHONY: all install uninstall clean reallyclean

LOCAL_CFLAGS+=
LOCAL_CPPFLAGS+=-DWITH_BROKER -I${R}/lib -I${R}/libcommon
LOCAL_LDFLAGS+=
LOCAL_LDADD+=-lcjson -lm ${LIBMOSQ_COMMON}

# ------------------------------------------
#  Platform specific
# ------------------------------------------
ifneq ($(or $(findstring $(UNAME),FreeBSD), $(findstring $(UNAME),OpenBSD), $(findstring $(UNAME),NetBSD)),)
	LOCAL_LDFLAGS+=-Wl,--dynamic-list=linker.syms
else
	LOCAL_LDADD+=-ldl
endif

ifeq ($(UNAME),Linux)
	LOCAL_LDADD+=-lrt
	LOCAL_LDFLAGS+=-Wl,--dynamic-list=linker.syms
endif

ifeq ($(UNAME),QNX)
	LOCAL_LDADD+= -lsocket
endif

# ------------------------------------------
#  Compile time options
# ------------------------------------------
include ${R}/make/broker.mk

# ------------------------------------------
#  Targets
# ------------------------------------------
ifeq ($(WITH_FUZZING),yes)
all : mosquitto_broker.a
else
all : mosquitto
endif

OBJS=	mosquitto.o \
		bridge.o \
		bridge_topic.o \
		broker_control.o \
		conf.o \
		conf_includedir.o \
		context.o \
		control.o \
		control_common.o \
		database.o \
		handle_auth.o \
		handle_connack.o \
		handle_connect.o \
		handle_disconnect.o \
		handle_publish.o \
		handle_subscribe.o \
		handle_unsubscribe.o \
		http_serv.o \
		keepalive.o \
		listeners.o \
		logging.o \
		loop.o \
		mux.o \
		mux_epoll.o \
		mux_kqueue.o \
		mux_poll.o \
		net.o \
		property_broker.o \
		persist_read.o \
		persist_read_v234.o \
		persist_read_v5.o \
		persist_write.o \
		persist_write_v5.o \
		plugin_callbacks.o \
		plugin_v2.o \
		plugin_v3.o \
		plugin_v4.o \
		plugin_v5.o \
		plugin_acl_check.o \
		plugin_basic_auth.o \
		plugin_cleanup.o \
		plugin_client_offline.o \
		plugin_connect.o \
		plugin_disconnect.o \
		plugin_extended_auth.o \
		plugin_init.o \
		plugin_message.o \
		plugin_persist.o \
		plugin_psk_key.o \
		plugin_public.o \
		plugin_subscribe.o \
		plugin_unsubscribe.o \
		plugin_tick.o \
		proxy_v1.o \
		proxy_v2.o \
		psk_file.o \
		read_handle.o \
		retain.o \
		security_default.o \
		send_auth.o \
		send_connack.o \
		send_suback.o \
		send_unsuback.o \
		service.o \
		session_expiry.o \
		signals.o \
		subs.o \
		sys_tree.o \
		topic_tok.o \
		websockets.o \
		will_delay.o \
		xtreport.o

OBJS_EXTERNAL= \
		alias_mosq.o \
		handle_ping.o \
		handle_pubackcomp.o \
		handle_pubrec.o \
		handle_pubrel.o \
		handle_suback.o \
		handle_unsuback.o \
		json_help.o \
		net_mosq.o \
		net_mosq_ocsp.o \
		net_ws.o \
		packet_datatypes.o \
		packet_mosq.o \
		property_mosq.o \
		send_connect.o \
		send_disconnect.o \
		send_mosq.o \
		send_publish.o \
		send_subscribe.o \
		send_unsubscribe.o \
		tls_mosq.o \
		util_mosq.o \
		will_mosq.o

ifeq ($(WITH_WEBSOCKETS),yes)
	OBJS_EXTERNAL+=${R}/deps/picohttpparser/picohttpparser.o
endif

mosquitto : ${OBJS} ${OBJS_EXTERNAL}
	${CROSS_COMPILE}${CC} ${LOCAL_LDFLAGS} $^ -o $@ $(LOCAL_LDADD)

mosquitto_broker.a : ${OBJS} ${OBJS_EXTERNAL}
	${CROSS_COMPILE}$(AR) cr $@ $^

${OBJS} : %.o: %.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

alias_mosq.o : ${R}/lib/alias_mosq.c ${R}/lib/alias_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

handle_ping.o : ${R}/lib/handle_ping.c ${R}/lib/read_handle.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

handle_pubackcomp.o : ${R}/lib/handle_pubackcomp.c ${R}/lib/read_handle.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

handle_pubrec.o : ${R}/lib/handle_pubrec.c ${R}/lib/read_handle.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

handle_pubrel.o : ${R}/lib/handle_pubrel.c ${R}/lib/read_handle.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

handle_suback.o : ${R}/lib/handle_suback.c ${R}/lib/read_handle.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

handle_unsuback.o : ${R}/lib/handle_unsuback.c ${R}/lib/read_handle.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

json_help.o : ${R}/common/json_help.c ${R}/common/json_help.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

net_mosq_ocsp.o : ${R}/lib/net_mosq_ocsp.c ${R}/lib/net_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

net_mosq.o : ${R}/lib/net_mosq.c ${R}/lib/net_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

net_ws.o : ${R}/lib/net_ws.c ${R}/lib/net_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

packet_datatypes.o : ${R}/lib/packet_datatypes.c ${R}/lib/packet_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

packet_mosq.o : ${R}/lib/packet_mosq.c ${R}/lib/packet_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

${R}/deps/picohttpparser/picohttpparser.o : ${R}/deps/picohttpparser/picohttpparser.c ${R}/deps/picohttpparser/picohttpparser.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

property_mosq.o : ${R}/lib/property_mosq.c ${R}/lib/property_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

send_connect.o : ${R}/lib/send_connect.c ${R}/lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

send_disconnect.o : ${R}/lib/send_disconnect.c ${R}/lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

send_mosq.o : ${R}/lib/send_mosq.c ${R}/lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

send_publish.o : ${R}/lib/send_publish.c ${R}/lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

send_subscribe.o : ${R}/lib/send_subscribe.c ${R}/lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

send_unsubscribe.o : ${R}/lib/send_unsubscribe.c ${R}/lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

tls_mosq.o : ${R}/lib/tls_mosq.c
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

util_mosq.o : ${R}/lib/util_mosq.c ${R}/lib/util_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

will_mosq.o : ${R}/lib/will_mosq.c ${R}/lib/will_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

install : all
	$(INSTALL) -d "${DESTDIR}$(prefix)/sbin"
	$(INSTALL) ${STRIP_OPTS} mosquitto "${DESTDIR}${prefix}/sbin/mosquitto"

uninstall :
	-rm -f "${DESTDIR}${prefix}/sbin/mosquitto"
	-rm -f "${DESTDIR}${prefix}/include/mosquitto_broker.h"
	-rm -f "${DESTDIR}${prefix}/include/mosquitto_plugin.h"

clean :
	-rm -f ${OBJS} ${OBJS_EXTERNAL} mosquitto mosquitto_broker.a *.gcda *.gcno

reallyclean : clean
	-rm -rf *.orig *.db
