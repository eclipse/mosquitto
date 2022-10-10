R=../..
include ${R}/config.mk

CFLAGS_FINAL=${CFLAGS} ${APP_CFLAGS} -I${R}/include -I${R}/ -I${R}/lib -I${R}/src -I${R}/deps -I${R}/common -DWITH_BROKER -DWITH_PERSISTENCE

OBJS = \
	   db_dump.o \
	   print.o \
	   \
	   memory_mosq.o \
	   memory_public.o \
	   packet_datatypes.o \
	   packet_mosq.o \
	   persist_read.o \
	   persist_read_v234.o \
	   persist_read_v5.o \
	   property_mosq.o \
	   send_disconnect.o \
	   stubs.o \
	   time_mosq.o \
	   topic_tok.o \
	   utf8_mosq.o

.PHONY: all clean reallyclean

all : mosquitto_db_dump

mosquitto_db_dump : ${OBJS}
	${CROSS_COMPILE}${CC} $^ -o $@ ${LDFLAGS} ${LIBS} ${APP_LDFLAGS}

db_dump.o : db_dump.c db_dump.h ${R}/src/persist.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

print.o : print.c db_dump.h ${R}/src/persist.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

memory_mosq.o : ${R}/lib/memory_mosq.c ${R}/lib/memory_mosq.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

memory_public.o : ${R}/src/memory_public.c
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

net_mosq.o : ${R}/lib/net_mosq.c ${R}/lib/net_mosq.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

packet_datatypes.o : ${R}/lib/packet_datatypes.c ${R}/lib/packet_mosq.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

packet_mosq.o : ${R}/lib/packet_mosq.c ${R}/lib/packet_mosq.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

persist_read.o : ${R}/src/persist_read.c ${R}/src/persist.h ${R}/src/mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

persist_read_v234.o : ${R}/src/persist_read_v234.c ${R}/src/persist.h ${R}/src/mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

persist_read_v5.o : ${R}/src/persist_read_v5.c ${R}/src/persist.h ${R}/src/mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

property_mosq.o : ${R}/lib/property_mosq.c ${R}/lib/property_mosq.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

read_handle.o : ${R}/src/read_handle.c
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

stubs.o : stubs.c
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

send_disconnect.o : ${R}/lib/send_disconnect.c
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

time_mosq.o : ${R}/common/time_mosq.c ${R}/common/time_mosq.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

topic_tok.o : ${R}/src/topic_tok.c
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

utf8_mosq.o : ${R}/lib/utf8_mosq.c
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

reallyclean: clean

clean :
	-rm -f *.o mosquitto_db_dump

install:

uninstall:
