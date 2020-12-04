include ../../config.mk

.PHONY: all install uninstall clean reallyclean

ifeq ($(WITH_SHARED_LIBRARIES),yes)
LIBMOSQ:=../../lib/libmosquitto.so.${SOVERSION}
else
LIBMOSQ:=../../lib/libmosquitto.a
endif

LOCAL_CPPFLAGS:=-I../mosquitto_passwd

OBJS=	mosquitto_ctrl.o \
		client.o \
		dynsec.o \
		dynsec_client.o \
		dynsec_group.o \
		dynsec_role.o \
		get_password.o \
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

all : $(TARGET)

mosquitto_ctrl : ${OBJS}
	${CROSS_COMPILE}${CC} ${APP_LDFLAGS} $^ -o $@ $(PASSWD_LDADD) $(LOCAL_LDFLAGS) $(LIBMOSQ) -lcjson -ldl

mosquitto_ctrl_example.so : ${EXAMPLE_OBJS}
	$(CROSS_COMPILE)$(CC) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) $(PLUGIN_LDFLAGS) -shared $< -o $@

mosquitto_ctrl.o : mosquitto_ctrl.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

client.o : client.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

dynsec.o : dynsec.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

dynsec_client.o : dynsec_client.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

dynsec_group.o : dynsec_group.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

dynsec_role.o : dynsec_role.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

example.o : example.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) -c $< -o $@

get_password.o : ../mosquitto_passwd/get_password.c ../mosquitto_passwd/get_password.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

memory_mosq.o : ../../lib/memory_mosq.c
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

memory_public.o : ../../src/memory_public.c
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

options.o : options.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

misc_mosq.o : ../../lib/misc_mosq.c ../../lib/misc_mosq.h
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

password_mosq.o : ../../src/password_mosq.c ../../src/password_mosq.h
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

install : all
	$(INSTALL) -d "${DESTDIR}$(prefix)/bin"
	$(INSTALL) ${STRIP_OPTS} mosquitto_ctrl "${DESTDIR}${prefix}/bin/mosquitto_ctrl"

uninstall :
	-rm -f "${DESTDIR}${prefix}/bin/mosquitto_ctrl"

clean :
	-rm -f *.o mosquitto_ctrl *.gcda *.gcno *.so

reallyclean : clean
	-rm -rf *.orig *.db
