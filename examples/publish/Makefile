R=../..
include ${R}/config.mk

.PHONY: all

all : basic-1 basic-websockets-1

basic-1 : basic-1.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${R}/lib/libmosquitto.so.${SOVERSION}

basic-websockets-1 : basic-websockets-1.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${R}/lib/libmosquitto.so.${SOVERSION}

basic-1.o : basic-1.c ${R}/lib/libmosquitto.so.${SOVERSION}
	${CROSS_COMPILE}${CC} -c $< -o $@ -I${R}/include ${CPPFLAGS} ${CFLAGS}

basic-websockets-1.o : basic-websockets-1.c ${R}/lib/libmosquitto.so.${SOVERSION}
	${CROSS_COMPILE}${CC} -c $< -o $@ -I${R}/include ${CPPFLAGS} ${CFLAGS}

${R}/lib/libmosquitto.so.${SOVERSION} :
	$(MAKE) -C ${R}/lib

clean :
	-rm -f *.o sub_single sub_multiple
