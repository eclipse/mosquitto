include ../../config.mk

CFLAGS_FINAL=${CFLAGS} -I../../include -I../../ -I../../lib -I../../src -I../../deps -DWITH_BROKER -DWITH_PERSISTENCE

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
	${CROSS_COMPILE}${CC} $^ -o $@ ${LDFLAGS} ${LIBS}

db_dump.o : db_dump.c db_dump.h ../../src/persist.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

print.o : print.c db_dump.h ../../src/persist.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

memory_mosq.o : ../../lib/memory_mosq.c ../../lib/memory_mosq.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

memory_public.o : ../../src/memory_public.c
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

net_mosq.o : ../../lib/net_mosq.c ../../lib/net_mosq.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

packet_datatypes.o : ../../lib/packet_datatypes.c ../../lib/packet_mosq.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

packet_mosq.o : ../../lib/packet_mosq.c ../../lib/packet_mosq.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

persist_read.o : ../../src/persist_read.c ../../src/persist.h ../../src/mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

persist_read_v234.o : ../../src/persist_read_v234.c ../../src/persist.h ../../src/mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

persist_read_v5.o : ../../src/persist_read_v5.c ../../src/persist.h ../../src/mosquitto_broker_internal.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

property_mosq.o : ../../lib/property_mosq.c ../../lib/property_mosq.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

read_handle.o : ../../src/read_handle.c
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

stubs.o : stubs.c
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

send_disconnect.o : ../../lib/send_disconnect.c
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

time_mosq.o : ../../lib/time_mosq.c
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

topic_tok.o : ../../src/topic_tok.c
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

utf8_mosq.o : ../../lib/utf8_mosq.c
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

reallyclean: clean

clean :
	-rm -f *.o mosquitto_db_dump

install:

uninstall:
