R=../..
include ${R}/config.mk

.PHONY: all install uninstall clean reallyclean

OBJS=	mosquitto_passwd.o \
		get_password.o \
		base64_mosq.o \
		memory_mosq.o \
		memory_public.o \
		misc_mosq.o \
		password_mosq.o

ifeq ($(WITH_TLS),yes)
ifeq ($(WITH_FUZZING),yes)
all : mosquitto_passwd.a
else
all : mosquitto_passwd
endif
else
all:
endif

mosquitto_passwd : ${OBJS}
	${CROSS_COMPILE}${CC} ${LDFLAGS} ${APP_LDFLAGS} $^ -o $@ $(PASSWD_LDADD)

mosquitto_passwd.a : ${OBJS}
	${CROSS_COMPILE}$(AR) cr $@ $^

mosquitto_passwd.o : mosquitto_passwd.c
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

get_password.o : get_password.c
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

base64_mosq.o : ${R}/common/base64_mosq.c ${R}/common/base64_mosq.h
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

memory_mosq.o : ${R}/lib/memory_mosq.c
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

memory_public.o : ${R}/src/memory_public.c
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

misc_mosq.o : ${R}/common/misc_mosq.c ${R}/common/misc_mosq.h
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

password_mosq.o : ${R}/common/password_mosq.c ${R}/common/password_mosq.h
	${CROSS_COMPILE}${CC} $(APP_CPPFLAGS) $(APP_CFLAGS) -c $< -o $@

install : all
ifeq ($(WITH_TLS),yes)
	$(INSTALL) -d "${DESTDIR}$(prefix)/bin"
	$(INSTALL) ${STRIP_OPTS} mosquitto_passwd "${DESTDIR}${prefix}/bin/mosquitto_passwd"
endif

uninstall :
	-rm -f "${DESTDIR}${prefix}/bin/mosquitto_passwd"

clean :
	-rm -f *.o *.a mosquitto_passwd *.gcda *.gcno

reallyclean : clean
	-rm -rf *.orig *.db
