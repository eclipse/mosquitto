R=../..
include ${R}/config.mk

LOCAL_CFLAGS+=
LOCAL_CPPFLAGS+=-I${R} -I${R}/lib -I${R}/src -I${R}/common -DWITH_BROKER
LOCAL_LDFLAGS+=
LOCAL_LDADD+=-lcjson -lm ${LIBMOSQ_COMMON}

# ------------------------------------------
#  Compile time options
# ------------------------------------------
include ${R}/make/broker.mk

# ------------------------------------------
#  Targets
# ------------------------------------------

OBJS = \
	db_dump.o \
	json.o \
	print.o \
	stubs.o

BROKER_OBJS = \
	${R}/src/packet_datatypes.o \
	${R}/src/persist_read.o \
	${R}/src/persist_read_v234.o \
	${R}/src/persist_read_v5.o \
	${R}/src/property_mosq.o \
	${R}/src/topic_tok.o

OBJS_EXTERNAL = \
	json_help.o

ifeq ($(UNAME),Linux)
    LIBS:=$(LIBS) -lrt
endif

.PHONY: all clean reallyclean

ifeq ($(WITH_FUZZING),yes)
all : mosquitto_db_dump.a
else
all : mosquitto_db_dump
endif

mosquitto_db_dump : ${OBJS} ${BROKER_OBJS} ${OBJS_EXTERNAL}
	${CROSS_COMPILE}${CC} $^ -o $@ ${LOCAL_LDFLAGS} ${LOCAL_LDADD}

mosquitto_db_dump.a : ${OBJS} ${BROKER_OBJS} ${OBJS_EXTERNAL}
	${CROSS_COMPILE}$(AR) cr $@ $^

${OBJS} : %.o:%.c db_dump.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

${BROKER_OBJS} :
	$(MAKE) -C ${R}/src $(notdir $@)

json_help.o : ${R}/common/json_help.c ${R}/common/json_help.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

reallyclean: clean

clean :
	-rm -f $(OBJS) $(OBJS_EXTERNAL) $(BROKER_OBJS)  mosquitto_db_dump mosquitto_db_dump.a *.gcda *.gcno

install:
	$(INSTALL) -d "${DESTDIR}$(prefix)/bin"
	$(INSTALL) ${STRIP_OPTS} mosquitto_db_dump "${DESTDIR}${prefix}/bin/mosquitto_db_dump"

uninstall:
