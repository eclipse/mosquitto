R=../..
include ${R}/config.mk

.PHONY : all binary check clean reallyclean test install uninstall

PLUGIN_NAME=mosquitto_persist_sqlite
LOCAL_CPPFLAGS=-I${R}/src/

OBJS=	\
		base_msgs.o \
		clients.o \
		client_msgs.o \
		init.o \
		plugin.o \
		restore.o \
		retain_msgs.o \
		subscriptions.o \
		tick.o

ifeq ($(WITH_SQLITE),yes)
ALL_DEPS:= binary
else
ALL_DEPS:=
endif

ifeq ($(WITH_CJSON),yes)
ALL_DEPS:=$(ALL_DEPS)
else
ALL_DEPS:=
endif

all : ${ALL_DEPS}
binary : ${PLUGIN_NAME}.so

${PLUGIN_NAME}.so : ${OBJS}
	${CROSS_COMPILE}${CC} $(PLUGIN_LDFLAGS) -fPIC -shared $^ -o $@ -lsqlite3

clients.o : clients.c persist_sqlite.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

client_msgs.o : client_msgs.c persist_sqlite.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

init.o : init.c persist_sqlite.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

base_msgs.o : base_msgs.c persist_sqlite.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

plugin.o : plugin.c persist_sqlite.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

restore.o : restore.c persist_sqlite.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

retain_msgs.o : retain_msgs.c persist_sqlite.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

subscriptions.o : subscriptions.c persist_sqlite.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

tick.o : tick.c persist_sqlite.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

reallyclean : clean
clean:
	-rm -f *.o ${PLUGIN_NAME}.so *.gcda *.gcno

check: test
test:

install: all
ifeq ($(WITH_SQLITE),yes)
ifeq ($(WITH_CJSON),yes)
	$(INSTALL) -d "${DESTDIR}$(libdir)"
	$(INSTALL) ${STRIP_OPTS} ${PLUGIN_NAME}.so "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"
endif
endif

uninstall :
	-rm -f "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"
