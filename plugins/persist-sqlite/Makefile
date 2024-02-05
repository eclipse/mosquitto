R=../..
include ${R}/config.mk

.PHONY : all binary check clean reallyclean test test-compile install uninstall

PLUGIN_NAME=mosquitto_persist_sqlite
LOCAL_CPPFLAGS+=-I${R}/src/ -I${R}/plugins/common
LOCAL_LIBADD+=-lsqlite3 -lcjson
LOCAL_LDFLAGS+=-fPIC -shared

OBJS = \
	base_msgs.o \
	clients.o \
	client_msgs.o \
	common.o \
	init.o \
	plugin.o \
	restore.o \
	retain_msgs.o \
	subscriptions.o \
	tick.o

OBJS_EXTERNAL = \
	json_help.o

ifeq ($(WITH_SQLITE),yes)
ALL_DEPS:= binary
else
ALL_DEPS:=
endif

all : ${ALL_DEPS}
binary : ${PLUGIN_NAME}.so

${PLUGIN_NAME}.so : ${OBJS} ${OBJS_EXTERNAL}
	${CROSS_COMPILE}${CC} $(LOCAL_LDFLAGS) $^ -o $@ ${LOCAL_LIBADD}

${OBJS} : %.o: %.c persist_sqlite.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

json_help.o : ${R}/common/json_help.c ${R}/common/json_help.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

reallyclean : clean
clean:
	-rm -f *.o ${PLUGIN_NAME}.so *.gcda *.gcno

test-compile:

check : test
test: test-compile

install: all
ifeq ($(WITH_SQLITE),yes)
	$(INSTALL) -d "${DESTDIR}$(libdir)"
	$(INSTALL) ${STRIP_OPTS} ${PLUGIN_NAME}.so "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"
endif

uninstall :
	-rm -f "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"
