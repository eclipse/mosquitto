R=../..
include ${R}/config.mk

.PHONY: all install uninstall clean reallyclean

LOCAL_CFLAGS+=
LOCAL_CPPFLAGS+=-I${R}/lib -I${R}/apps/mosquitto_passwd -I${R}/plugins/dynamic-security -I${R}/common
LOCAL_LDFLAGS+=
LOCAL_LDADD+=-lcjson -ldl ${LIBMOSQ} ${LIBMOSQ_COMMON} -lcrypto -lssl

# ------------------------------------------
#  Compile time options
# ------------------------------------------

ifeq ($(WITH_SOCKS),yes)
	LOCAL_CPPFLAGS+=-DWITH_SOCKS
endif

ifeq ($(WITH_THREADING),yes)
LOCAL_LDFLAGS+=-pthread
endif


ifeq ($(WITH_EDITLINE),yes)
LOCAL_LDADD+=-ledit
LOCAL_CPPFLAGS+=-DWITH_CTRL_SHELL -DWITH_EDITLINE
endif

OBJS= \
	mosquitto_ctrl.o \
	broker.o \
	client.o \
	dynsec.o \
	dynsec_client.o \
	dynsec_group.o \
	dynsec_role.o \
	options.o

ifeq ($(WITH_EDITLINE),yes)
OBJS+= \
	ctrl_shell.o \
	ctrl_shell_broker.o \
	ctrl_shell_client.o \
	ctrl_shell_completion_tree.o \
	ctrl_shell_dynsec.o \
	ctrl_shell_io.o \
	ctrl_shell_post_connect.o \
	ctrl_shell_pre_connect.o \
	ctrl_shell_printf.o
endif

OBJS_EXTERNAL= \
	get_password.o \
	json_help.o

EXAMPLE_OBJS= example.o

TARGET:=mosquitto_ctrl mosquitto_ctrl_example.so

all : ${TARGET}

mosquitto_ctrl : ${OBJS} ${OBJS_EXTERNAL}
	${CROSS_COMPILE}${CC} $^ -o $@ $(LOCAL_LDFLAGS) $(LOCAL_LDADD)

mosquitto_ctrl_example.so : ${EXAMPLE_OBJS}
	$(CROSS_COMPILE)$(CC) $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) ${LOCAL_LDFLAGS} -fPIC -shared $< -o $@

${OBJS} : %.o: %.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

example.o : example.c mosquitto_ctrl.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -fPIC -c $< -o $@

get_password.o : ${R}/apps/mosquitto_passwd/get_password.c ${R}/apps/mosquitto_passwd/get_password.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

json_help.o : ${R}/common/json_help.c ${R}/common/json_help.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

${R}/lib/libmosquitto.so.${SOVERSION} :
	$(MAKE) -C ${R}/lib

${R}/lib/libmosquitto.a :
	$(MAKE) -C ${R}/lib libmosquitto.a

install : all
ifeq ($(WITH_TLS),yes)
	$(INSTALL) -d "${DESTDIR}$(prefix)/bin"
	$(INSTALL) ${STRIP_OPTS} mosquitto_ctrl "${DESTDIR}${prefix}/bin/mosquitto_ctrl"
endif

uninstall :
	-rm -f "${DESTDIR}${prefix}/bin/mosquitto_ctrl"

clean :
	-rm -f *.o mosquitto_ctrl *.gcda *.gcno *.so

reallyclean : clean
	-rm -rf *.orig *.db
