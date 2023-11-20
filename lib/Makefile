R=..
include ${R}/config.mk

LOCAL_CFLAGS+=-fPIC
LOCAL_CPPFLAGS+=
LOCAL_LDFLAGS+=-Wl,--version-script=linker.version -Wl,-soname,libmosquitto.so.$(SOVERSION) -fPIC -shared
LOCAL_LIBADD+=-lcjson -lc ${LIB_ARGON2}
STATIC_LIB_DEPS:=

# ------------------------------------------
#  Compile time options
# ------------------------------------------

ifeq ($(WITH_SOCKS),yes)
	LOCAL_CPPFLAGS+=-DWITH_SOCKS
endif

ifeq ($(WITH_SRV),yes)
	LOCAL_CPPFLAGS+=-DWITH_SRV
	LOCAL_LIBADD+=-lcares
	STATIC_LIB_DEPS+=-lcares
endif

ifeq ($(WITH_THREADING),yes)
	LOCAL_CFLAGS+=-pthread
	LOCAL_CPPFLAGS+=-DWITH_THREADING
	LOCAL_LDFLAGS+=-pthread
	STATIC_LIB_DEPS+=-pthread
endif

ifeq ($(WITH_TLS),yes)
	LOCAL_LIBADD+=-lssl -lcrypto
	STATIC_LIB_DEPS:=$(STATIC_LIB_DEPS) -lssl -lcrypto
endif

# ------------------------------------------
#  Targets
# ------------------------------------------
.PHONY : really clean install

OBJS= \
	mosquitto.o \
	actions_publish.o \
	actions_subscribe.o \
	actions_unsubscribe.o \
	alias_mosq.o \
	callbacks.o \
	connect.o \
	handle_auth.o \
	handle_connack.o \
	handle_disconnect.o \
	handle_ping.o \
	handle_pubackcomp.o \
	handle_publish.o \
	handle_pubrec.o \
	handle_pubrel.o \
	handle_suback.o \
	handle_unsuback.o \
	helpers.o \
	http_client.o \
	logging_mosq.o \
	loop.o \
	memory_mosq.o \
	messages_mosq.o \
	net_mosq_ocsp.o \
	net_mosq.o \
	net_ws.o \
	options.o \
	packet_datatypes.o \
	packet_mosq.o \
	property_mosq.o \
	read_handle.o \
	send_connect.o \
	send_disconnect.o \
	send_mosq.o \
	send_publish.o \
	send_subscribe.o \
	send_unsubscribe.o \
	socks_mosq.o \
	srv_mosq.o \
	strings_mosq.o \
	thread_mosq.o \
	tls_mosq.o \
	utf8_mosq.o \
	util_mosq.o \
	util_topic.o \
	will_mosq.o

OBJS_EXTERNAL= \
	base64_mosq.o \
	misc_mosq.o \
	password_mosq.o \
	time_mosq.o

ifeq ($(WITH_WEBSOCKETS),yes)
	OBJS_EXTERNAL+=${R}/deps/picohttpparser/picohttpparser.o
endif

ALL_DEPS:=

ifeq ($(WITH_SHARED_LIBRARIES),yes)
	ALL_DEPS+=libmosquitto.so.${SOVERSION}
endif

ifeq ($(WITH_STATIC_LIBRARIES),yes)
	ALL_DEPS+=libmosquitto.a
endif

all : ${ALL_DEPS}
ifeq ($(WITH_SHARED_LIBRARIES),yes)
	$(MAKE) -C cpp
endif

install : all
	$(INSTALL) -d "${DESTDIR}${libdir}/"
ifeq ($(WITH_SHARED_LIBRARIES),yes)
	$(INSTALL) ${STRIP_OPTS} libmosquitto.so.${SOVERSION} "${DESTDIR}${libdir}/libmosquitto.so.${SOVERSION}"
	ln -sf libmosquitto.so.${SOVERSION} "${DESTDIR}${libdir}/libmosquitto.so"
endif
ifeq ($(WITH_STATIC_LIBRARIES),yes)
	$(INSTALL) ${STRIP_OPTS} libmosquitto.a "${DESTDIR}${libdir}/libmosquitto.a"
endif
	$(INSTALL) -d "${DESTDIR}${incdir}/"
	$(INSTALL) ${R}/include/mosquitto.h "${DESTDIR}${incdir}/mosquitto.h"
	$(INSTALL) ${R}/include/mqtt_protocol.h "${DESTDIR}${incdir}/mqtt_protocol.h"
	$(INSTALL) -d "${DESTDIR}${libdir}/pkgconfig"
	$(INSTALL) -m644 ${R}/libmosquitto.pc.in "${DESTDIR}${libdir}/pkgconfig/libmosquitto.pc"
	sed ${SEDINPLACE} -e "s#@CMAKE_INSTALL_PREFIX@#${prefix}#" -e "s#@VERSION@#${VERSION}#" "${DESTDIR}${libdir}/pkgconfig/libmosquitto.pc"
ifeq ($(WITH_SHARED_LIBRARIES),yes)
	$(MAKE) -C cpp install
endif

uninstall :
	-rm -f "${DESTDIR}${libdir}/libmosquitto.so.${SOVERSION}"
	-rm -f "${DESTDIR}${libdir}/libmosquitto.so"
	-rm -f "${DESTDIR}${libdir}/libmosquitto.a"
	-rm -f "${DESTDIR}${incdir}/mosquitto.h"

reallyclean : clean

clean :
	-rm -f ${OBJS} ${OBJS_EXTERNAL} libmosquitto.so.${SOVERSION} libmosquitto.so libmosquitto.a *.gcno *.gcda
	$(MAKE) -C cpp clean

libmosquitto.so.${SOVERSION} : ${OBJS} ${OBJS_EXTERNAL}
	${CROSS_COMPILE}$(CC) $(LOCAL_LDFLAGS) $^ -o $@ ${LOCAL_LIBADD}

libmosquitto.a : ${OBJS} ${OBJS_EXTERNAL}
	${CROSS_COMPILE}$(AR) cr $@ $^

${OBJS} : %.o: %.c ${R}/include/mosquitto.h mosquitto_internal.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

base64_mosq.o : ${R}/common/base64_mosq.c ${R}/common/base64_mosq.h
	${CROSS_COMPILE}$(CC) $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

misc_mosq.o : ${R}/common/misc_mosq.c ${R}/common/misc_mosq.h
	${CROSS_COMPILE}$(CC) $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

password_mosq.o : ${R}/common/password_mosq.c net_mosq.h
	${CROSS_COMPILE}$(CC) $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

time_mosq.o : ${R}/common/time_mosq.c ${R}/common/time_mosq.h
	${CROSS_COMPILE}$(CC) $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@
