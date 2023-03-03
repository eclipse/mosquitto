R=../..
include ${R}/config.mk

.PHONY: all test

ifeq ($(WITH_SHARED_LIBRARIES),yes)
LIB_DEP:=${R}/lib/libmosquitto.so.${SOVERSION}
else
LIB_DEP:=${R}/lib/libmosquitto.a
endif

all : auth_plugin.so

auth_plugin.so : auth_plugin.c
	$(CC) ${CFLAGS} -fPIC -shared $< -o $@ -I${R}/lib -I${R}/src

${R}/lib/libmosquitto.so.${SOVERSION} :
	$(MAKE) -C ${R}/lib

${R}/lib/libmosquitto.a :
	$(MAKE) -C ${R}/lib libmosquitto.a

clean :
	-rm -f *.o random_client *.gcda *.gcno

test : all
	./test.py
