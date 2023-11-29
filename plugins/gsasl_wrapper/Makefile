R=../..
include ${R}/config.mk

.PHONY : all binary check clean reallyclean test test-compile install uninstall

PLUGIN_NAME=mosquitto_gsasl_adapter

CFLAGS+=-fPIC
LIBADD+=-lgsasl

OBJS = simple_plugin.o

all : binary

binary : ${PLUGIN_NAME}.so

${PLUGIN_NAME}.so : ${OBJS} ${OBJS_EXTERNAL}
	${CROSS_COMPILE}${CC} $(LDFLAGS) -fPIC -shared $^ -o $@ ${LIBADD}

${PLUGIN_NAME}.a : ${OBJS} ${OBJS_EXTERNAL}
	${CROSS_COMPILE}$(AR) cr $@ $^

${OBJS} : %.o: %.c
	${CROSS_COMPILE}${CC} $(CPPFLAGS) $(CFLAGS) -c $< -o $@

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
