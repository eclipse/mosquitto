R=../..
include ${R}/config.mk

.PHONY: all

all : sub_callback sub_single sub_multiple

sub_callback : callback.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${R}/lib/libmosquitto.so.${SOVERSION}

sub_single : single.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${R}/lib/libmosquitto.so.${SOVERSION}

sub_multiple : multiple.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${R}/lib/libmosquitto.so.${SOVERSION}

callback.o : callback.c ${R}/lib/libmosquitto.so.${SOVERSION}
	${CROSS_COMPILE}${CC} -c $< -o $@ -I${R}/lib ${CFLAGS}

single.o : single.c ${R}/lib/libmosquitto.so.${SOVERSION}
	${CROSS_COMPILE}${CC} -c $< -o $@ -I${R}/lib ${CFLAGS}

multiple.o : multiple.c ${R}/lib/libmosquitto.so.${SOVERSION}
	${CROSS_COMPILE}${CC} -c $< -o $@ -I${R}/lib ${CFLAGS}

${R}/lib/libmosquitto.so.${SOVERSION} :
	$(MAKE) -C ${R}/lib

clean :
	-rm -f *.o sub_single sub_multiple
