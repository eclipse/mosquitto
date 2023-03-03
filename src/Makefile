R=..
include ${R}/config.mk

.PHONY: all install uninstall clean reallyclean

BROKER_CFLAGS:=$(BROKER_CFLAGS) $(CFLAGS)
BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) $(CPPFLAGS)
BROKER_LDFLAGS:=$(BROKER_LDFLAGS) $(LDFLAGS)

ifeq ($(WITH_FUZZING),yes)
all : mosquitto_broker.a
else
all : mosquitto
endif

OBJS=	mosquitto.o \
		alias_mosq.o \
		base64_mosq.o \
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
		handle_ping.o \
		handle_pubackcomp.o \
		handle_publish.o \
		handle_pubrec.o \
		handle_pubrel.o \
		handle_suback.o \
		handle_subscribe.o \
		handle_unsuback.o \
		handle_unsubscribe.o \
		http_serv.o \
		json_help.o \
		keepalive.o \
		listeners.o \
		logging.o \
		loop.o \
		memory_mosq.o \
		memory_public.o \
		misc_mosq.o \
		mux.o \
		mux_epoll.o \
		mux_kqueue.o \
		mux_poll.o \
		net.o \
		net_mosq.o \
		net_mosq_ocsp.o \
		net_ws.o \
		packet_datatypes.o \
		packet_mosq.o \
		password_mosq.o \
		property_broker.o \
		property_mosq.o \
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
		read_handle.o \
		retain.o \
		security_default.o \
		send_auth.o \
		send_connack.o \
		send_connect.o \
		send_disconnect.o \
		send_mosq.o \
		send_publish.o \
		send_suback.o \
		send_subscribe.o \
		send_unsuback.o \
		send_unsubscribe.o \
		service.o \
		session_expiry.o \
		signals.o \
		strings_mosq.o \
		subs.o \
		sys_tree.o \
		time_mosq.o \
		topic_tok.o \
		tls_mosq.o \
		utf8_mosq.o \
		util_mosq.o \
		util_topic.o \
		websockets.o \
		will_delay.o \
		will_mosq.o \
		xtreport.o

ifeq ($(WITH_WEBSOCKETS),yes)
	OBJS+=${R}/deps/picohttpparser/picohttpparser.o
endif

mosquitto : ${OBJS}
	${CROSS_COMPILE}${CC} ${BROKER_LDFLAGS} $^ -o $@ $(BROKER_LDADD)

mosquitto_broker.a : ${OBJS}
	${CROSS_COMPILE}$(AR) cr $@ $^

mosquitto.o : mosquitto.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

alias_mosq.o : ${R}/lib/alias_mosq.c ${R}/lib/alias_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

base64_mosq.o : ${R}/common/base64_mosq.c ${R}/common/base64_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

bridge.o : bridge.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

bridge_topic.o : bridge_topic.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

broker_control.o : broker_control.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

conf.o : conf.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

conf_includedir.o : conf_includedir.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

context.o : context.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

control.o : control.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

control_common.o : ${R}/common/control_common.c ${R}/common/control_common.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

database.o : database.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_auth.o : handle_auth.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_connack.o : handle_connack.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_connect.o : handle_connect.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_disconnect.o : handle_disconnect.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_ping.o : ${R}/lib/handle_ping.c ${R}/lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_pubackcomp.o : ${R}/lib/handle_pubackcomp.c ${R}/lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_publish.o : handle_publish.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_pubrec.o : ${R}/lib/handle_pubrec.c ${R}/lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_pubrel.o : ${R}/lib/handle_pubrel.c ${R}/lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_suback.o : ${R}/lib/handle_suback.c ${R}/lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_subscribe.o : handle_subscribe.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_unsuback.o : ${R}/lib/handle_unsuback.c ${R}/lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_unsubscribe.o : handle_unsubscribe.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

http_serv.o : http_serv.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

json_help.o : ${R}/common/json_help.c ${R}/common/json_help.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

keepalive.o : keepalive.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

listeners.o : listeners.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

logging.o : logging.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

loop.o : loop.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

memory_mosq.o : ${R}/lib/memory_mosq.c ${R}/lib/memory_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

memory_public.o : memory_public.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

misc_mosq.o : ${R}/common/misc_mosq.c ${R}/common/misc_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

mux.o : mux.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

mux_epoll.o : mux_epoll.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

mux_kqueue.o : mux_kqueue.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

mux_poll.o : mux_poll.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

net.o : net.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

net_mosq_ocsp.o : ${R}/lib/net_mosq_ocsp.c ${R}/lib/net_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

net_mosq.o : ${R}/lib/net_mosq.c ${R}/lib/net_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

net_ws.o : ${R}/lib/net_ws.c ${R}/lib/net_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

password_mosq.o : ${R}/common/password_mosq.c ${R}/common/password_mosq.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

persist_read.o : persist_read.c persist.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

persist_read_v234.o : persist_read_v234.c persist.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

persist_read_v5.o : persist_read_v5.c persist.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

persist_write.o : persist_write.c persist.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

persist_write_v5.o : persist_write_v5.c persist.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

packet_datatypes.o : ${R}/lib/packet_datatypes.c ${R}/lib/packet_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

packet_mosq.o : ${R}/lib/packet_mosq.c ${R}/lib/packet_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

${R}/deps/picohttpparser/picohttpparser.o : ${R}/deps/picohttpparser/picohttpparser.c ${R}/deps/picohttpparser/picohttpparser.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

property_broker.o : property_broker.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

property_mosq.o : ${R}/lib/property_mosq.c ${R}/lib/property_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_callbacks.o : plugin_callbacks.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_v2.o : plugin_v2.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_v3.o : plugin_v3.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_v4.o : plugin_v4.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_v5.o : plugin_v5.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_acl_check.o : plugin_acl_check.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_basic_auth.o : plugin_basic_auth.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_cleanup.o : plugin_cleanup.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_connect.o : plugin_connect.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_disconnect.o : plugin_disconnect.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_extended_auth.o : plugin_extended_auth.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_init.o : plugin_init.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_message.o : plugin_message.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_persist.o : plugin_persist.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_psk_key.o : plugin_psk_key.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_public.o : plugin_public.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_subscribe.o : plugin_subscribe.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_tick.o : plugin_tick.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_unsubscribe.o : plugin_unsubscribe.c ${R}/include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

read_handle.o : read_handle.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

retain.o : retain.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

security_default.o : security_default.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_auth.o : send_auth.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_connect.o : ${R}/lib/send_connect.c ${R}/lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_disconnect.o : ${R}/lib/send_disconnect.c ${R}/lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_connack.o : send_connack.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_mosq.o : ${R}/lib/send_mosq.c ${R}/lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_publish.o : ${R}/lib/send_publish.c ${R}/lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_suback.o : send_suback.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_subscribe.o : ${R}/lib/send_subscribe.c ${R}/lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_unsuback.o : send_unsuback.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_unsubscribe.o : ${R}/lib/send_unsubscribe.c ${R}/lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

service.o : service.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

session_expiry.o : session_expiry.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

signals.o : signals.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

strings_mosq.o : ${R}/lib/strings_mosq.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

subs.o : subs.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

sys_tree.o : sys_tree.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

time_mosq.o : ${R}/common/time_mosq.c ${R}/common/time_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

tls_mosq.o : ${R}/lib/tls_mosq.c
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

topic_tok.o : topic_tok.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

util_mosq.o : ${R}/lib/util_mosq.c ${R}/lib/util_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

util_topic.o : ${R}/lib/util_topic.c ${R}/lib/util_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

utf8_mosq.o : ${R}/lib/utf8_mosq.c
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

websockets.o : websockets.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

will_delay.o : will_delay.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

will_mosq.o : ${R}/lib/will_mosq.c ${R}/lib/will_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

xtreport.o : xtreport.c
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

install : all
	$(INSTALL) -d "${DESTDIR}$(prefix)/sbin"
	$(INSTALL) ${STRIP_OPTS} mosquitto "${DESTDIR}${prefix}/sbin/mosquitto"
	$(INSTALL) -d "${DESTDIR}$(prefix)/include"
	$(INSTALL) ${R}/include/mosquitto_broker.h "${DESTDIR}${prefix}/include/mosquitto_broker.h"
	$(INSTALL) ${R}/include/mosquitto_plugin.h "${DESTDIR}${prefix}/include/mosquitto_plugin.h"

uninstall :
	-rm -f "${DESTDIR}${prefix}/sbin/mosquitto"
	-rm -f "${DESTDIR}${prefix}/include/mosquitto_broker.h"
	-rm -f "${DESTDIR}${prefix}/include/mosquitto_plugin.h"

clean :
	-rm -f *.o mosquitto mosquitto_broker.a *.gcda *.gcno

reallyclean : clean
	-rm -rf *.orig *.db
