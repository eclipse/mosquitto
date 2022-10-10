R=../..
CFLAGS=-Wall -ggdb
LDFLAGS=${R}/lib/libmosquitto.so.1 -lmysqlclient

.PHONY: all clean

all : mosquitto_mysql_log

mosquitto_mysql_log : mysql_log.o
	${CC} $^ -o $@ ${LDFLAGS}

mysql_log.o : mysql_log.c
	${CC} -c $^ -o $@ ${CFLAGS} -I${R}/lib

clean :
	-rm -f *.o mosquitto_mysql_log
