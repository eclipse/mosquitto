R=../..
include ${R}/config.mk

CC=cc
CFLAGS=-I${R}/src -I${R}/include -I. -I${R} -Wall -ggdb -DDEBUG -DWITH_CLIENT
LDFLAGS=
SOVERSION=1

.PHONY: all test clean

all : msgsps_pub msgsps_sub

msgsps_pub : msgsps_pub.o
	${CC} $^ -o $@ ${R}/lib/libmosquitto.so.${SOVERSION}

msgsps_pub.o : msgsps_pub.c msgsps_common.h
	${CC} $(CFLAGS) -c $< -o $@

msgsps_sub : msgsps_sub.o
	${CC} $^ -o $@ ${R}/lib/libmosquitto.so.${SOVERSION}

msgsps_sub.o : msgsps_sub.c msgsps_common.h
	${CC} $(CFLAGS) -c $< -o $@

clean :
	-rm -f *.o msgsps_pub msgsps_sub
