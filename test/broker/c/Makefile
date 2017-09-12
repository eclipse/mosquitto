.PHONY: all test clean reallyclean 08

CFLAGS=-I../../../lib -I../../../src -Wall -Werror

all : auth_plugin.so auth_plugin_v2.so 08

08 : 08-tls-psk-pub.test 08-tls-psk-bridge.test

auth_plugin.so : auth_plugin.c
	$(CC) ${CFLAGS} -fPIC -shared $^ -o $@ 

auth_plugin_v2.so : auth_plugin_v2.c
	$(CC) ${CFLAGS} -fPIC -shared $^ -o $@ 

08-tls-psk-pub.test : 08-tls-psk-pub.c
	$(CC) ${CFLAGS} $^ -o $@ ../../../lib/libmosquitto.so.1

08-tls-psk-bridge.test : 08-tls-psk-bridge.c
	$(CC) ${CFLAGS} $^ -o $@ ../../../lib/libmosquitto.so.1


reallyclean : clean
	-rm -f *.orig

clean :
	rm -f *.so *.test
