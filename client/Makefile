R=..
include ${R}/config.mk

.PHONY: all install uninstall reallyclean clean static static_pub static_sub static_rr

CLIENT_CFLAGS:=$(CLIENT_CFLAGS) $(CFLAGS)
CLIENT_CPPFLAGS:=$(CLIENT_CPPFLAGS) $(CPPFLAGS)
CLIENT_LDFLAGS:=$(CLIENT_LDFLAGS) $(LDFLAGS)

ifeq ($(WITH_SHARED_LIBRARIES),yes)
SHARED_DEP:=${R}/lib/libmosquitto.so.${SOVERSION}
endif

ifeq ($(WITH_SHARED_LIBRARIES),yes)
ALL_DEPS:= mosquitto_pub mosquitto_sub mosquitto_rr
else
ifeq ($(WITH_STATIC_LIBRARIES),yes)
ALL_DEPS:= static_pub static_sub static_rr
endif
endif

all : ${ALL_DEPS}

static : static_pub static_sub static_rr
	# This makes mosquitto_pub/sub/rr versions that are statically linked with
	# libmosquitto only.

static_pub : pub_client.o pub_shared.o client_props.o client_shared.o ${R}/lib/libmosquitto.a
	${CROSS_COMPILE}${CC} $^ -o mosquitto_pub ${CLIENT_LDFLAGS} ${STATIC_LIB_DEPS} ${CLIENT_STATIC_LDADD}

static_sub : sub_client.o sub_client_output.o client_props.o client_shared.o ${R}/lib/libmosquitto.a
	${CROSS_COMPILE}${CC} $^ -o mosquitto_sub ${CLIENT_LDFLAGS} ${STATIC_LIB_DEPS} ${CLIENT_STATIC_LDADD}

static_rr : rr_client.o client_props.o client_shared.o pub_shared.o sub_client_output.o ${R}/lib/libmosquitto.a
	${CROSS_COMPILE}${CC} $^ -o mosquitto_rr ${CLIENT_LDFLAGS} ${STATIC_LIB_DEPS} ${CLIENT_STATIC_LDADD}

mosquitto_pub : pub_client.o pub_shared.o client_shared.o client_props.o
	${CROSS_COMPILE}${CC} $(CLIENT_LDFLAGS) $^ -o $@ $(CLIENT_LDADD)

mosquitto_sub : sub_client.o sub_client_output.o client_shared.o client_props.o
	${CROSS_COMPILE}${CC} $(CLIENT_LDFLAGS) $^ -o $@ $(CLIENT_LDADD)

mosquitto_rr : rr_client.o client_shared.o client_props.o pub_shared.o sub_client_output.o
	${CROSS_COMPILE}${CC} $(CLIENT_LDFLAGS) $^ -o $@ $(CLIENT_LDADD)

pub_client.o : pub_client.c ${SHARED_DEP}
	${CROSS_COMPILE}${CC} $(CLIENT_CPPFLAGS) $(CLIENT_CFLAGS) -c $< -o $@

pub_shared.o : pub_shared.c ${SHARED_DEP}
	${CROSS_COMPILE}${CC} $(CLIENT_CPPFLAGS) $(CLIENT_CFLAGS) -c $< -o $@

sub_client.o : sub_client.c ${SHARED_DEP}
	${CROSS_COMPILE}${CC} $(CLIENT_CPPFLAGS) $(CLIENT_CFLAGS) -c $< -o $@

sub_client_output.o : sub_client_output.c sub_client_output.h ${SHARED_DEP}
	${CROSS_COMPILE}${CC} $(CLIENT_CPPFLAGS) $(CLIENT_CFLAGS) -c $< -o $@

rr_client.o : rr_client.c ${SHARED_DEP}
	${CROSS_COMPILE}${CC} $(CLIENT_CPPFLAGS) $(CLIENT_CFLAGS) -c $< -o $@

client_shared.o : client_shared.c client_shared.h
	${CROSS_COMPILE}${CC} $(CLIENT_CPPFLAGS) $(CLIENT_CFLAGS) -c $< -o $@

client_props.o : client_props.c client_shared.h
	${CROSS_COMPILE}${CC} $(CLIENT_CPPFLAGS) $(CLIENT_CFLAGS) -c $< -o $@

# The "testing" target is intended to make it easy to compile a quick client
# for testing purposes. testing.c should not be committed as a file.
testing : testing.o
	${CROSS_COMPILE}${CC} $(CLIENT_LDFLAGS) $^ -o $@ $(CLIENT_LDADD) $(CLIENT_LDFLAGS)

testing.o : testing.c
	${CROSS_COMPILE}${CC} $(CLIENT_CPPFLAGS) $(CLIENT_CFLAGS) -c $< -o $@


${R}/lib/libmosquitto.so.${SOVERSION} :
	$(MAKE) -C ${R}/lib

${R}/lib/libmosquitto.a :
	$(MAKE) -C ${R}/lib libmosquitto.a

install : all
	$(INSTALL) -d "${DESTDIR}$(prefix)/bin"
	$(INSTALL) ${STRIP_OPTS} mosquitto_pub "${DESTDIR}${prefix}/bin/mosquitto_pub"
	$(INSTALL) ${STRIP_OPTS} mosquitto_sub "${DESTDIR}${prefix}/bin/mosquitto_sub"
	$(INSTALL) ${STRIP_OPTS} mosquitto_rr "${DESTDIR}${prefix}/bin/mosquitto_rr"

uninstall :
	-rm -f "${DESTDIR}${prefix}/bin/mosquitto_pub"
	-rm -f "${DESTDIR}${prefix}/bin/mosquitto_sub"
	-rm -f "${DESTDIR}${prefix}/bin/mosquitto_rr"

reallyclean : clean

clean :
	-rm -f *.o mosquitto_pub mosquitto_sub mosquitto_rr *.gcda *.gcno
