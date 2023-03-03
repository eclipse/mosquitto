R=../..
include ${R}/config.mk

.PHONY: all install uninstall clean reallyclean

ifeq ($(WITH_SHARED_LIBRARIES),yes)
LIBMOSQ:=${R}/lib/libmosquitto.so.${SOVERSION}
else
ifeq ($(WITH_THREADING),yes)
LIBMOSQ:=${R}/lib/libmosquitto.a -lpthread -lssl -lcrypto
else
LIBMOSQ:=${R}/lib/libmosquitto.a
endif
endif

LOCAL_LDFLAGS:=${LDFLAGS}
LOCAL_CPPFLAGS:=-I${R}/apps/mosquitto_passwd -I${R}/plugins/dynamic-security -DWITH_CJSON -I${R}/plugins/common -I${R}/common
ifeq ($(WITH_BUNDLED_DEPS),yes)
LOCAL_CPPFLAGS+=-I${R}/deps
endif

OBJS=	mosquitto_ctrl.o \
		base64_mosq.o \
		broker.o \
		client.o \
		dynsec.o \
		dynsec_client.o \
		dynsec_group.o \
		dynsec_hash.o \
		dynsec_role.o \
		get_password.o \
		json_help.o \
		memory_mosq.o \
		memory_public.o \
		options.o \
		password_mosq.o

EXAMPLE_OBJS= example.o

ifeq ($(WITH_TLS),yes)
ifeq ($(WITH_CJSON),yes)
TARGET:=mosquitto_ctrl mosquitto_ctrl_example.so
else
TARGET:=
endif

else
TARGET:=
endif

all : ${TARGET}

mosquitto_ctrl : ${OBJS} ${LIBMOSQ}
	${CROSS_COMPILE}${CC} ${APP_LDFLAGS} $^ -o $@ $(PASSWD_LDADD) $(LOCAL_LDFLAGS) $(LIBMOSQ) -lcjson -ldl

mosquitto_ctrl_example.so : ${EXAMPLE_OBJS}
	$(CROSS_COMPILE)$(CC) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) $(PLUGIN_LDFLAGS) ${LOCAL_LDFLAGS} -shared $< -o $@

mosquitto_ctrl.o : mosquitto_ctrl.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

base64_mosq.o : ${R}/common/base64_mosq.c ${R}/common/base64_mosq.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

broker.o : broker.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

client.o : client.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

dynsec.o : dynsec.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

dynsec_hash.o : ${R}/plugins/dynamic-security/hash.c ${R}/plugins/dynamic-security/dynamic_security.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

dynsec_client.o : dynsec_client.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

dynsec_group.o : dynsec_group.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

dynsec_role.o : dynsec_role.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

example.o : example.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

get_password.o : ${R}/apps/mosquitto_passwd/get_password.c ${R}/apps/mosquitto_passwd/get_password.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

json_help.o : ${R}/common/json_help.c ${R}/common/json_help.h
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -DWITH_CJSON=yes -c $< -o $@

memory_mosq.o : ${R}/lib/memory_mosq.c
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

memory_public.o : ${R}/src/memory_public.c
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

options.o : options.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

password_mosq.o : ${R}/common/password_mosq.c ${R}/common/password_mosq.h
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

${R}/lib/libmosquitto.so.${SOVERSION} :
	$(MAKE) -C ${R}/lib

${R}/lib/libmosquitto.a :
	$(MAKE) -C ${R}/lib libmosquitto.a

install : all
ifeq ($(WITH_TLS),yes)
ifeq ($(WITH_CJSON),yes)
	$(INSTALL) -d "${DESTDIR}$(prefix)/bin"
	$(INSTALL) ${STRIP_OPTS} mosquitto_ctrl "${DESTDIR}${prefix}/bin/mosquitto_ctrl"
endif
endif

uninstall :
	-rm -f "${DESTDIR}${prefix}/bin/mosquitto_ctrl"

clean :
	-rm -f *.o mosquitto_ctrl *.gcda *.gcno *.so

reallyclean : clean
	-rm -rf *.orig *.db
