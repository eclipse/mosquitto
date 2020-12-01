include ../config.mk

.PHONY: all install uninstall clean reallyclean

all : mosquitto

OBJS=	mosquitto.o \
		alias_mosq.o \
		bridge.o \
		bridge_topic.o \
		conf.o \
		conf_includedir.o \
		context.o \
		control.o \
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
		keepalive.o \
		logging.o \
		loop.o \
		memory_mosq.o \
		memory_public.o \
		misc_mosq.o \
		mux.o \
		mux_epoll.o \
		mux_poll.o \
		net.o \
		net_mosq.o \
		net_mosq_ocsp.o \
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
		plugin.o \
		plugin_public.o \
		read_handle.o \
		retain.o \
		security.o \
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

mosquitto : ${OBJS}
	${CROSS_COMPILE}${CC} ${BROKER_LDFLAGS} $^ -o $@ $(BROKER_LDADD)

mosquitto.o : mosquitto.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

alias_mosq.o : ../lib/alias_mosq.c ../lib/alias_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

bridge.o : bridge.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

bridge_topic.o : bridge_topic.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

conf.o : conf.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

conf_includedir.o : conf_includedir.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

context.o : context.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

control.o : control.c mosquitto_broker_internal.h
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

handle_ping.o : ../lib/handle_ping.c ../lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_pubackcomp.o : ../lib/handle_pubackcomp.c ../lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_publish.o : handle_publish.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_pubrec.o : ../lib/handle_pubrec.c ../lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_pubrel.o : ../lib/handle_pubrel.c ../lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_suback.o : ../lib/handle_suback.c ../lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_subscribe.o : handle_subscribe.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_unsuback.o : ../lib/handle_unsuback.c ../lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

handle_unsubscribe.o : handle_unsubscribe.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

keepalive.o : keepalive.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

logging.o : logging.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

loop.o : loop.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

memory_mosq.o : ../lib/memory_mosq.c ../lib/memory_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

memory_public.o : memory_public.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

misc_mosq.o : ../lib/misc_mosq.c ../lib/misc_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

mux.o : mux.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

mux_epoll.o : mux_epoll.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

mux_poll.o : mux_poll.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

net.o : net.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

net_mosq_ocsp.o : ../lib/net_mosq_ocsp.c ../lib/net_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

net_mosq.o : ../lib/net_mosq.c ../lib/net_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

password_mosq.o : password_mosq.c password_mosq.h mosquitto_broker_internal.h
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

packet_datatypes.o : ../lib/packet_datatypes.c ../lib/packet_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

packet_mosq.o : ../lib/packet_mosq.c ../lib/packet_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

property_broker.o : property_broker.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

property_mosq.o : ../lib/property_mosq.c ../lib/property_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin.o : plugin.c ../include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_public.o : plugin_public.c ../include/mosquitto_plugin.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

read_handle.o : read_handle.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

retain.o : retain.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

security.o : security.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

security_default.o : security_default.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_auth.o : send_auth.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_connect.o : ../lib/send_connect.c ../lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_disconnect.o : ../lib/send_disconnect.c ../lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_connack.o : send_connack.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_mosq.o : ../lib/send_mosq.c ../lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_publish.o : ../lib/send_publish.c ../lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_suback.o : send_suback.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_subscribe.o : ../lib/send_subscribe.c ../lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_unsuback.o : send_unsuback.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

send_unsubscribe.o : ../lib/send_unsubscribe.c ../lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

service.o : service.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

session_expiry.o : session_expiry.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

signals.o : signals.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

strings_mosq.o : ../lib/strings_mosq.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

subs.o : subs.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

sys_tree.o : sys_tree.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

time_mosq.o : ../lib/time_mosq.c ../lib/time_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

tls_mosq.o : ../lib/tls_mosq.c
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

topic_tok.o : topic_tok.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

util_mosq.o : ../lib/util_mosq.c ../lib/util_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

util_topic.o : ../lib/util_topic.c ../lib/util_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

utf8_mosq.o : ../lib/utf8_mosq.c
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

websockets.o : websockets.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

will_delay.o : will_delay.c mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

will_mosq.o : ../lib/will_mosq.c ../lib/will_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

xtreport.o : xtreport.c
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) -c $< -o $@

plugin_defer.so : plugin_defer.c ../include/mosquitto_plugin.h ../include/mosquitto_broker.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} -I. -I../lib -fPIC -shared $< -o $@

plugin_debug.so : plugin_debug.c ../include/mosquitto_plugin.../include/h mosquitto_broker.h mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} -I. -I../lib -fPIC -shared $< -o $@

install : all
	$(INSTALL) -d "${DESTDIR}$(prefix)/sbin"
	$(INSTALL) ${STRIP_OPTS} mosquitto "${DESTDIR}${prefix}/sbin/mosquitto"
	$(INSTALL) -d "${DESTDIR}$(prefix)/include"
	$(INSTALL) ../include/mosquitto_broker.h "${DESTDIR}${prefix}/include/mosquitto_broker.h"
	$(INSTALL) ../include/mosquitto_plugin.h "${DESTDIR}${prefix}/include/mosquitto_plugin.h"

uninstall :
	-rm -f "${DESTDIR}${prefix}/sbin/mosquitto"
	-rm -f "${DESTDIR}${prefix}/include/mosquitto_broker.h"
	-rm -f "${DESTDIR}${prefix}/include/mosquitto_plugin.h"

clean : 
	-rm -f *.o mosquitto *.gcda *.gcno

reallyclean : clean
	-rm -rf *.orig *.db
