R=../../..
include ${R}/config.mk

.PHONY : all binary check clean reallyclean test install uninstall

PLUGIN_NAME=mosquitto_plugin_event_stats
PLUGIN_CFLAGS+=-I${R}/include -I${R}/

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
ifdef INSTALL_$(call INSTALL_PLUGIN_GUARD,$(notdir $(CURDIR)))_PLUGIN
	# Only install example plugins if explicitly asked for them to be by setting INSTALL_[UPPERCASED_PLUGIN_NAME_WITH_UNDERSCORES]_PLUGIN environment variable when invoking make
	$(INSTALL) -d "${DESTDIR}$(libdir)"
	$(INSTALL) ${STRIP_OPTS} ${PLUGIN_NAME}.so "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"
endif

uninstall :
	-rm -f "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"
