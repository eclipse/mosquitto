include ../../config.mk

.PHONY : all binary check clean reallyclean test install uninstall

PLUGIN_NAME=mosquitto_dynamic_bridge
LOCAL_CPPFLAGS=-I../../src/ -I../../lib/ -DWITH_CJSON -DWITH_BRIDGE

OBJS=	\
		dynamic_bridge.o \
		json_help.o \
		plugin.o

ifeq ($(WITH_CJSON),yes)
ifeq ($(WITH_BRIDGE),yes)
ALL_DEPS:= binary
else
ALL_DEPS:=
endif
else
ALL_DEPS:=
endif

all : ${ALL_DEPS}
binary : ${PLUGIN_NAME}.so

${PLUGIN_NAME}.so : ${OBJS}
	${CROSS_COMPILE}${CC} $(PLUGIN_LDFLAGS) -fPIC -shared $^ -o $@ -lcjson

dynamic_bridge.o : dynamic_bridge.c dynamic_bridge.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

json_help.o : json_help.c
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

plugin.o : plugin.c dynamic_bridge.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

reallyclean : clean
clean:
	-rm -f *.o ${PLUGIN_NAME}.so *.gcda *.gcno

check: test
test:

install: all
ifeq ($(WITH_CJSON),yes)
ifeq ($(WITH_BRIDGE),yes)
	$(INSTALL) -d "${DESTDIR}$(libdir)"
	$(INSTALL) ${STRIP_OPTS} ${PLUGIN_NAME}.so "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"
endif
endif

uninstall :
	-rm -f "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"
