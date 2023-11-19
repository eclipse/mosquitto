R=../..
include ${R}/config.mk

.PHONY : all binary check clean reallyclean test test-compile install uninstall

PLUGIN_NAME=mosquitto_dynamic_security

LOCAL_CFLAGS+=-fPIC
LOCAL_CPPFLAGS+=-I${R}/lib/ -I${R}/src/ -I${R}/plugins/common
LOCAL_LIBADD+=-lcjson
LOCAL_LDFLAGS+=-fPIC -shared

WITH_PW_CACHE:=yes
ifeq ($(WITH_PW_CACHE),yes)
        LOCAL_CPPFLAGS+=-DWITH_PW_CACHE
endif

OBJS = \
	acl.o \
	auth.o \
	clients.o \
	clientlist.o \
	config.o \
	config_init.o \
	control.o \
	default_acl.o \
	groups.o \
	grouplist.o \
	kicklist.o \
	plugin.o \
	roles.o \
	rolelist.o \
	tick.o

OBJS_EXTERNAL = \
	base64_mosq.o \
	json_help.o \
	misc_mosq.o \
	password_mosq.o \

ifeq ($(WITH_TLS),yes)
ALL_DEPS:= binary
else
ALL_DEPS:=
endif

all : ${ALL_DEPS}

ifeq ($(WITH_FUZZING),yes)
binary : ${PLUGIN_NAME}.a
else
binary : ${PLUGIN_NAME}.so
endif

ifeq ($(WITH_FUZZING),yes)
binary : ${PLUGIN_NAME}.a
else
binary : ${PLUGIN_NAME}.so
endif

${PLUGIN_NAME}.a : ${OBJS} ${OBJS_EXTERNAL}
	${CROSS_COMPILE}$(AR) cr $@ $^

${PLUGIN_NAME}.so : ${OBJS} ${OBJS_EXTERNAL}
	${CROSS_COMPILE}${CC} $(LOCAL_LDFLAGS) $^ -o $@ ${LOCAL_LIBADD}

${OBJS} : %.o: %.c dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

base64_mosq.o : ${R}/common/base64_mosq.c ${R}/common/base64_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

json_help.o : ${R}/common/json_help.c ${R}/common/json_help.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

misc_mosq.o : ${R}/common/misc_mosq.c ${R}/common/misc_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

password_mosq.o : ${R}/common/password_mosq.c ${R}/common/password_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

reallyclean : clean
clean:
	-rm -f *.o ${PLUGIN_NAME}.so *.gcda *.gcno

test-compile:

check: test
test: test-compile

install: all
ifeq ($(WITH_TLS),yes)
	$(INSTALL) -d "${DESTDIR}$(libdir)"
	$(INSTALL) ${STRIP_OPTS} ${PLUGIN_NAME}.so "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"
endif

uninstall :
	-rm -f "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"
