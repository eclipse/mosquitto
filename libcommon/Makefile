R=..
include ${R}/config.mk

LOCAL_CFLAGS+=-fPIC
LOCAL_CPPFLAGS+=
LOCAL_LDFLAGS+=-Wl,--version-script=linker.version -Wl,-soname,libmosquitto_common.so.$(SOVERSION) -fPIC
LOCAL_LIBADD+=-lcjson

ifeq ($(WITH_MEMORY_TRACKING),yes)
	LOCAL_CPPFLAGS+=-DWITH_MEMORY_TRACKING
endif

ifeq ($(ALLOC_MISMATCH_INVALID_READ),yes)
	LOCAL_CPPFLAGS+=-DALLOC_MISMATCH_INVALID_READ
endif

ifeq ($(ALLOC_MISMATCH_ABORT),yes)
	LOCAL_CPPFLAGS+=-DALLOC_MISMATCH_ABORT
endif

ifeq ($(WITH_TLS),yes)
	LOCAL_LIBADD+=-lcrypto
endif

# ------------------------------------------
#  Targets
# ------------------------------------------
.PHONY : really clean install

OBJS= \
	base64_common.o \
	cjson_common.o \
	file_common.o \
	memory_common.o \
	mqtt_common.o \
	password_common.o \
	property_common.o \
	random_common.o \
	strings_common.o \
	time_common.o \
	topic_common.o \
	utf8_common.o

all : libmosquitto_common.a libmosquitto_common.so.${SOVERSION}

install :
	$(INSTALL) -d "${DESTDIR}${libdir}/"
	$(INSTALL) ${STRIP_OPTS} libmosquitto_common.so.${SOVERSION} "${DESTDIR}${libdir}/libmosquitto_common.so.${SOVERSION}"
	ln -sf libmosquitto_common.so.${SOVERSION} "${DESTDIR}${libdir}/libmosquitto_common.so"

uninstall :

reallyclean : clean

clean :
	-rm -f ${OBJS} libmosquitto_common.so.${SOVERSION} libmosquitto_common.so libmosquitto_common.a *.gcno *.gcda

libmosquitto_common.so.${SOVERSION} : ${OBJS}
	${CROSS_COMPILE}$(CC) $(LOCAL_LDFLAGS) $^ -o $@ ${LOCAL_LIBADD} -shared

libmosquitto_common.a : ${OBJS}
	${CROSS_COMPILE}$(AR) cr $@ $^

${OBJS} : %.o: %.c
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@
