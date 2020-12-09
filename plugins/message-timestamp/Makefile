include ../../config.mk

.PHONY : all binary check clean reallyclean test install uninstall

PLUGIN_NAME=mosquitto_message_timestamp

all : binary

binary : ${PLUGIN_NAME}.so

${PLUGIN_NAME}.so : ${PLUGIN_NAME}.c
	$(CROSS_COMPILE)$(CC) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) $(PLUGIN_LDFLAGS) -fPIC -shared $< -o $@

reallyclean : clean
clean:
	-rm -f *.o ${PLUGIN_NAME}.so *.gcda *.gcno

check: test
test:

install: ${PLUGIN_NAME}.so
	# Don't install, these are examples only.
	#$(INSTALL) -d "${DESTDIR}$(prefix)/lib"
	#$(INSTALL) ${STRIP_OPTS} ${PLUGIN_NAME}.so "${DESTDIR}${prefix}/lib/${PLUGIN_NAME}.so"

uninstall :
	-rm -f "${DESTDIR}${prefix}/lib/${PLUGIN_NAME}.so"
