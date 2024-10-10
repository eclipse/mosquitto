R=../..
include ${R}/config.mk

.PHONY : all binary check clean reallyclean test install uninstall

PLUGIN_NAME=mosquitto_auth_by_hmac
LOCAL_CPPFLAGS=-I${R}/lib/ -I${R}/src/ -I${R}/plugins/common -I$(CURDIR)
ifeq ($(WITH_BUNDLED_DEPS),yes)
	LOCAL_CPPFLAGS:=$(LOCAL_CPPFLAGS) -I${R}/deps
endif

ifeq ($(WITH_TLS),yes)
LOCAL_CPPFLAGS += -DWITH_TLS
endif

OBJS = base64_mosq.o auth_by_hmac.o

all : binary

binary : ${PLUGIN_NAME}.so

${PLUGIN_NAME}.so : ${OBJS}
	${CROSS_COMPILE}${CC} $(PLUGIN_LDFLAGS) -fPIC -shared $^ -o $@ $(PLUGIN_LIBS)

base64_mosq.o : ${R}/common/base64_mosq.c ${R}/common/base64_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

auth_by_hmac.o : auth_by_hmac.c
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

reallyclean : clean
clean:
	-rm -f *.o ${PLUGIN_NAME}.so *.gcda *.gcno

check: test
test:

install: ${PLUGIN_NAME}.so
	# Don't install, these are examples only.
	#$(INSTALL) -d "${DESTDIR}$(libdir)"
	#$(INSTALL) ${STRIP_OPTS} ${PLUGIN_NAME}.so "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"

uninstall :
	-rm -f "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"
