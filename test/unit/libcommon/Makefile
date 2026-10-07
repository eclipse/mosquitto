R=../../..
include ${R}/config.mk

.PHONY: all check test test-compile clean coverage

LOCAL_CFLAGS+=-coverage
LOCAL_CPPFLAGS+=-I${R}/libcommon -DTEST_SOURCE_DIR='"$(realpath .)"'
LOCAL_LDFLAGS+=-coverage
LOCAL_LDADD+=-lcunit ${LIBMOSQ_COMMON}

ifeq ($(WITH_TLS),yes)
	LOCAL_LDADD+=-lssl -lcrypto
endif

TEST_OBJS = \
	base64_test.o \
	file_test.o \
	property_add.o \
	property_value.o \
	strings_test.o \
	test.o \
	topic_test.o \
	trim_test.o \
	utf8.o

LIB_OBJS =


all : test-compile

check : test

libcommon_test : ${TEST_OBJS} ${LIB_OBJS}
	$(CROSS_COMPILE)$(CC) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LDADD)

${TEST_OBJS} : %.o: %.c
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

lib_stubs.o : stubs.c
	${CROSS_COMPILE}$(CC) $(LIB_LOCAL_CPPFLAGS) $(LIB_LOCAL_CFLAGS) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

build : libcommon_test

test : build
	./libcommon_test

test-compile: build

clean :
	-rm -rf libcommon_test
	-rm -rf *.o *.gcda *.gcno coverage.info
