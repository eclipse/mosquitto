R=../..
include ${R}/config.mk

LOCAL_CFLAGS+=
LOCAL_CPPFLAGS+=-I${R}/lib -I${R}/src -I${R}/common -DWITH_BROKER
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

.PHONY: all clean reallyclean

ifeq ($(WITH_FUZZING),yes)
all : mosquitto_db_dump.a
else
all : mosquitto_db_dump
endif

mosquitto_db_dump : ${OBJS} ${BROKER_OBJS}
	${CROSS_COMPILE}${CC} $^ -o $@ ${LOCAL_LDFLAGS} ${LOCAL_LDADD}

mosquitto_db_dump.a : ${OBJS} ${BROKER_OBJS}
	${CROSS_COMPILE}$(AR) cr $@ $^

${OBJS} : %.o:%.c db_dump.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

${BROKER_OBJS} :
	$(MAKE) -C ${R}/src $(notdir $@)

reallyclean: clean

clean :
	-rm -f $(OBJS) $(BROKER_OBJS)  mosquitto_db_dump mosquitto_db_dump.a *.gcda *.gcno

install:

uninstall:
