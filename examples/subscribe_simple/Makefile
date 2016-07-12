include ../../config.mk

.PHONY: all

all : sub_callback sub_single sub_multiple

sub_callback : callback.o
	${CROSS_COMPILE}${CC} $^ -o $@ ../../lib/libmosquitto.so.${SOVERSION}

sub_single : single.o
	${CROSS_COMPILE}${CC} $^ -o $@ ../../lib/libmosquitto.so.${SOVERSION}

sub_multiple : multiple.o
	${CROSS_COMPILE}${CC} $^ -o $@ ../../lib/libmosquitto.so.${SOVERSION}

callback.o : callback.c ../../lib/libmosquitto.so.${SOVERSION}
	${CROSS_COMPILE}${CC} -c $< -o $@ -I../../lib ${CFLAGS}

single.o : single.c ../../lib/libmosquitto.so.${SOVERSION}
	${CROSS_COMPILE}${CC} -c $< -o $@ -I../../lib ${CFLAGS}

multiple.o : multiple.c ../../lib/libmosquitto.so.${SOVERSION}
	${CROSS_COMPILE}${CC} -c $< -o $@ -I../../lib ${CFLAGS}

../../lib/libmosquitto.so.${SOVERSION} :
	$(MAKE) -C ../../lib

clean : 
	-rm -f *.o sub_single sub_multiple
