include ../../config.mk

.PHONY: all install uninstall clean reallyclean

OBJS=	mosquitto_passwd.o \
		get_password.o \
		memory_mosq.o \
		memory_public.o \
		misc_mosq.o \
		password_mosq.o

ifeq ($(WITH_TLS),yes)
all: mosquitto_passwd
else
all:
endif

mosquitto_passwd : ${OBJS}
	${CROSS_COMPILE}${CC} ${APP_LDFLAGS} $^ -o $@ $(PASSWD_LDADD)

mosquitto_passwd.o : mosquitto_passwd.c
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

get_password.o : get_password.c
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

memory_mosq.o : ../../lib/memory_mosq.c
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

memory_public.o : ../../src/memory_public.c
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

misc_mosq.o : ../../lib/misc_mosq.c ../../lib/misc_mosq.h
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

password_mosq.o : ../../src/password_mosq.c ../../src/password_mosq.h
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

install : all
	$(INSTALL) -d "${DESTDIR}$(prefix)/bin"
	$(INSTALL) ${STRIP_OPTS} mosquitto_passwd "${DESTDIR}${prefix}/bin/mosquitto_passwd"

uninstall :
	-rm -f "${DESTDIR}${prefix}/bin/mosquitto_passwd"

clean :
	-rm -f *.o mosquitto_passwd *.gcda *.gcno

reallyclean : clean
	-rm -rf *.orig *.db
