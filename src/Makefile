include ../config.mk

.PHONY: all install uninstall clean reallyclean

ifeq ($(WITH_TLS),yes)
all : mosquitto mosquitto_passwd
else
all : mosquitto
endif

OBJS=	mosquitto.o \
		bridge.o \
		conf.o \
		context.o \
		database.o \
		handle_connack.o \
		handle_connect.o \
		handle_ping.o \
		handle_pubackcomp.o \
		handle_publish.o \
		handle_pubrec.o \
		handle_pubrel.o \
		handle_suback.o \
		handle_subscribe.o \
		handle_unsuback.o \
		handle_unsubscribe.o \
		logging.o \
		loop.o \
		memory_mosq.o \
		persist.o \
		net.o \
		net_mosq.o \
		packet_mosq.o \
		read_handle.o \
		security.o \
		security_default.o \
		send_connack.o \
		send_connect.o \
		send_disconnect.o \
		send_mosq.o \
		send_publish.o \
		send_suback.o \
		send_subscribe.o \
		send_unsubscribe.o \
		service.o \
		signals.o \
		subs.o \
		sys_tree.o \
		time_mosq.o \
		tls_mosq.o \
		utf8_mosq.o \
		util_mosq.o \
		websockets.o \
		will_mosq.o

mosquitto : ${OBJS}
	${CROSS_COMPILE}${CC} $^ -o $@ ${LDFLAGS} $(BROKER_LIBS)

mosquitto.o : mosquitto.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

bridge.o : bridge.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@
	
conf.o : conf.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@
	
context.o : context.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

database.o : database.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

handle_connack.o : handle_connack.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

handle_connect.o : handle_connect.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

handle_ping.o : ../lib/handle_ping.c ../lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

handle_pubackcomp.o : ../lib/handle_pubackcomp.c ../lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

handle_publish.o : handle_publish.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

handle_pubrec.o : ../lib/handle_pubrec.c ../lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

handle_pubrel.o : ../lib/handle_pubrel.c ../lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

handle_suback.o : ../lib/handle_suback.c ../lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

handle_subscribe.o : handle_subscribe.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

handle_unsuback.o : ../lib/handle_unsuback.c ../lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

handle_unsubscribe.o : handle_unsubscribe.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

logging.o : logging.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

loop.o : loop.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

memory_mosq.o : ../lib/memory_mosq.c ../lib/memory_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

net.o : net.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

net_mosq.o : ../lib/net_mosq.c ../lib/net_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@
	
persist.o : persist.c persist.h mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@
	
packet_mosq.o : ../lib/packet_mosq.c ../lib/packet_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

read_handle.o : read_handle.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

security.o : security.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

security_default.o : security_default.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

send_connect.o : ../lib/send_connect.c ../lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

send_disconnect.o : ../lib/send_disconnect.c ../lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

send_connack.o : send_connack.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

send_mosq.o : ../lib/send_mosq.c ../lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

send_publish.o : ../lib/send_publish.c ../lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

send_suback.o : send_suback.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

send_subscribe.o : ../lib/send_subscribe.c ../lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

send_unsubscribe.o : ../lib/send_unsubscribe.c ../lib/send_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

service.o : service.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

signals.o : signals.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

subs.o : subs.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

sys_tree.o : sys_tree.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

time_mosq.o : ../lib/time_mosq.c ../lib/time_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

tls_mosq.o : ../lib/tls_mosq.c
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

util_mosq.o : ../lib/util_mosq.c ../lib/util_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

utf8_mosq.o : ../lib/utf8_mosq.c
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

websockets.o : websockets.c mosquitto_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

will_mosq.o : ../lib/will_mosq.c ../lib/will_mosq.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

mosquitto_passwd : mosquitto_passwd.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${LDFLAGS} $(PASSWD_LIBS)

mosquitto_passwd.o : mosquitto_passwd.c
	${CROSS_COMPILE}${CC} $(CFLAGS) ${CPPFLAGS} -c $< -o $@

install : all
	$(INSTALL) -d ${DESTDIR}$(prefix)/sbin
	$(INSTALL) ${STRIP_OPTS} mosquitto ${DESTDIR}${prefix}/sbin/mosquitto
	$(INSTALL) -d ${DESTDIR}$(prefix)/include
	$(INSTALL) mosquitto_plugin.h ${DESTDIR}${prefix}/include/mosquitto_plugin.h
ifeq ($(WITH_TLS),yes)
	$(INSTALL) -d ${DESTDIR}$(prefix)/bin
	$(INSTALL) ${STRIP_OPTS} mosquitto_passwd ${DESTDIR}${prefix}/bin/mosquitto_passwd
endif

uninstall :
	-rm -f ${DESTDIR}${prefix}/sbin/mosquitto
	-rm -f ${DESTDIR}${prefix}/include/mosquitto_plugin.h
	-rm -f ${DESTDIR}${prefix}/bin/mosquitto_passwd

clean : 
	-rm -f *.o mosquitto mosquitto_passwd

reallyclean : clean
	-rm -rf *.orig *.db
