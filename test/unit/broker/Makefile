R=../../..
include ${R}/config.mk
include ${R}/make/broker.mk
include ${R}/make/unit-test.mk

.PHONY: all check test test-compile clean coverage

LOCAL_CFLAGS+=-coverage -ggdb
LOCAL_CPPFLAGS+=-DWITH_BROKER -I${R}/src -I${R}/test -I${R}/lib -DTEST_SOURCE_DIR='"$(realpath .)"' -I${R}/lib -I${R}/libcommon
LOCAL_LDFLAGS+=-coverage
LOCAL_LDADD+=-lcunit ${LIBMOSQ_COMMON}

ifeq ($(WITH_TLS),yes)
	LOCAL_LDADD+=-lssl -lcrypto
endif

BRIDGE_TOPIC_TEST_OBJS = \
		bridge_topic_test.o \
		stubs.o \

BRIDGE_TOPIC_OBJS = \
		${R}/src/bridge_topic.o \
		${R}/src/packet_datatypes.o \
		${R}/src/property_mosq.o

KEEPALIVE_TEST_OBJS = \
		keepalive_stubs.o \
		keepalive_test.o

KEEPALIVE_OBJS =

PERSIST_READ_TEST_OBJS = \
		persist_read_test.o \
		persist_read_stubs.o

PERSIST_READ_OBJS = \
		${R}/src/database.o \
		${R}/src/packet_datatypes.o \
		${R}/src/persist_read.o \
		${R}/src/persist_read_v234.o \
		${R}/src/persist_read_v5.o \
		${R}/src/property_mosq.o \
		${R}/src/retain.o \
		${R}/src/topic_tok.o \
		${R}/src/util_mosq.o

PERSIST_WRITE_TEST_OBJS = \
		persist_write_test.o \
		persist_write_stubs.o

PERSIST_WRITE_OBJS = \
		${R}/src/database.o \
		${R}/src/packet_datatypes.o \
		${R}/src/packet_mosq.o \
		${R}/src/persist_read.o \
		${R}/src/persist_read_v234.o \
		${R}/src/persist_read_v5.o \
		${R}/src/persist_write.o \
		${R}/src/persist_write_v5.o \
		${R}/src/property_mosq.o \
		${R}/src/retain.o \
		${R}/src/subs.o \
		${R}/src/topic_tok.o \
		${R}/src/util_mosq.o

SUBS_TEST_OBJS = \
		subs_test.o \
		subs_stubs.o

SUBS_OBJS = \
		${R}/src/database.o \
		${R}/src/packet_datatypes.o \
		${R}/src/property_mosq.o \
		${R}/src/subs.o \
		${R}/src/topic_tok.o

all : test-compile

check : test

bridge_topic_test : ${BRIDGE_TOPIC_TEST_OBJS} ${BRIDGE_TOPIC_OBJS}
	$(CROSS_COMPILE)$(CC) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LDADD)

keepalive_test : ${KEEPALIVE_TEST_OBJS} ${KEEPALIVE_OBJS}
	$(CROSS_COMPILE)$(CC) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LDADD)

persist_read_test : ${PERSIST_READ_TEST_OBJS} ${PERSIST_READ_OBJS}
	$(CROSS_COMPILE)$(CC) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LDADD)

persist_write_test : ${PERSIST_WRITE_TEST_OBJS} ${PERSIST_WRITE_OBJS}
	$(CROSS_COMPILE)$(CC) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LDADD)

subs_test : ${SUBS_TEST_OBJS} ${SUBS_OBJS}
	$(CROSS_COMPILE)$(CC) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LDADD)


${BRIDGE_TOPIC_TEST_OBJS} : %.o: %.c
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

${KEEPALIVE_TEST_OBJS} : %.o: %.c
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

${PERSIST_READ_TEST_OBJS} : %.o: %.c
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

${PERSIST_WRITE_TEST_OBJS} : %.o: %.c
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

${SUBS_TEST_OBJS} : %.o: %.c
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@


${R}/src/bridge_topic.o : ${R}/src/bridge_topic.c
	$(MAKE) -C ${R}/src/ bridge_topic.o

${R}/src/database.o : ${R}/src/database.c
	$(MAKE) -C ${R}/src/ database.o

${R}/src/packet_datatypes.o : ${R}/lib/packet_datatypes.c
	$(MAKE) -C ${R}/src/ packet_datatypes.o

${R}/src/packet_mosq.o : ${R}/lib/packet_mosq.c
	$(MAKE) -C ${R}/src/ packet_mosq.o

${R}/src/persist_read.o : ${R}/src/persist_read.c
	$(MAKE) -C ${R}/src/ persist_read.o

${R}/src/persist_read_v234.o : ${R}/src/persist_read_v234.c
	$(MAKE) -C ${R}/src/ persist_read_v234.o

${R}/src/persist_read_v5.o : ${R}/src/persist_read_v5.c
	$(MAKE) -C ${R}/src/ persist_read_v5.o

${R}/src/persist_write.o : ${R}/src/persist_write.c
	$(MAKE) -C ${R}/src/ persist_write.o

${R}/src/persist_write_v5.o : ${R}/src/persist_write_v5.c
	$(MAKE) -C ${R}/src/ persist_write_v5.o

${R}/src/property_mosq.o : ${R}/lib/property_mosq.c
	$(MAKE) -C ${R}/src/ property_mosq.o

${R}/src/retain.o : ${R}/src/retain.c
	$(MAKE) -C ${R}/src/ retain.o

${R}/src/subs.o : ${R}/src/subs.c
	$(MAKE) -C ${R}/src/ subs.o

${R}/src/topic_tok.o : ${R}/src/topic_tok.c
	$(MAKE) -C ${R}/src/ topic_tok.o

${R}/src/util_mosq.o : ${R}/lib/util_mosq.c
	$(MAKE) -C ${R}/src/ util_mosq.o

ALL_TESTS:=bridge_topic_test keepalive_test persist_read_test persist_write_test subs_test

build : ${ALL_TESTS}

test : build
	set -e; for t in ${ALL_TESTS}; do ${SANITIZER_COMMAND} ./$${t}; done

test-compile: build

clean :
	-rm -rf mosq_test bridge_topic_test keepalive_test persist_read_test persist_write_test subs_test
	-rm -rf *.o *.gcda *.gcno coverage.info *.vglog out/

coverage :
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory out
