R=../..
include ${R}/config.mk

.PHONY: all check test test-broker test-compile test-lib clean coverage

CPPFLAGS:=$(CPPFLAGS) -I${R} -I${R}/include -I${R}/lib -I${R}/src -I${R}/common -I${R}/test
ifeq ($(WITH_BUNDLED_DEPS),yes)
        CPPFLAGS:=$(CPPFLAGS) -I${R}/deps
endif

CFLAGS:=$(CFLAGS) -Wall -ggdb -D TEST_SOURCE_DIR='"$(realpath .)"' -coverage
LDFLAGS:=$(LDFLAGS) -coverage
LDADD:=$(LDADD) -lcunit
ifeq ($(WITH_TLS),yes)
	LDADD:=$(LDADD) -lssl -lcrypto
endif

TEST_OBJS = \
		test.o \
		datatype_read.o \
		datatype_write.o \
		misc_trim_test.o \
		property_add.o \
		property_read.o \
		property_user_read.o \
		property_write.o \
		strings_test.o \
		lib_stubs.o \
		util_topic_test.o \
		utf8.o

LIB_OBJS = \
		${R}/lib/memory_mosq.o \
		${R}/lib/misc_mosq.o \
		${R}/lib/packet_datatypes.o \
		${R}/lib/packet_mosq.o \
		${R}/lib/property_mosq.o \
		${R}/lib/strings_mosq.o \
		${R}/lib/util_mosq.o \
		${R}/lib/util_topic.o \
		${R}/lib/utf8_mosq.o

BRIDGE_TOPIC_TEST_OBJS = \
		bridge_topic_test.o \
		broker_stubs.o \

BRIDGE_TOPIC_OBJS = \
		${R}/src/bridge_topic.o \
		${R}/src/memory_mosq.o \
		${R}/src/memory_public.o \
		${R}/src/util_topic.o \

KEEPALIVE_TEST_OBJS = \
		keepalive_stubs.o \
		keepalive_test.o

KEEPALIVE_OBJS = \
		${R}/src/memory_mosq.o

PERSIST_READ_TEST_OBJS = \
		persist_read_test.o \
		persist_read_stubs.o

PERSIST_READ_OBJS = \
		${R}/src/memory_mosq.o \
		${R}/src/memory_public.o \
		${R}/src/misc_mosq.o \
		${R}/src/packet_datatypes.o \
		${R}/src/persist_read.o \
		${R}/src/persist_read_v234.o \
		${R}/src/persist_read_v5.o \
		${R}/src/property_mosq.o \
		${R}/src/retain.o \
		${R}/src/topic_tok.o \
		${R}/src/utf8_mosq.o \
		${R}/src/util_mosq.o

PERSIST_WRITE_TEST_OBJS = \
		persist_write_test.o \
		persist_write_stubs.o

PERSIST_WRITE_OBJS = \
		${R}/src/database.o \
		${R}/src/memory_mosq.o \
		${R}/src/memory_public.o \
		${R}/src/misc_mosq.o \
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
		${R}/src/utf8_mosq.o \
		${R}/src/util_mosq.o

SUBS_TEST_OBJS = \
		subs_test.o \
		subs_stubs.o

SUBS_OBJS = \
		${R}/src/database.o \
		${R}/src/memory_mosq.o \
		${R}/src/memory_public.o \
		${R}/src/packet_datatypes.o \
		${R}/src/property_mosq.o \
		${R}/src/subs.o \
		${R}/src/topic_tok.o \
		${R}/src/utf8_mosq.o \

all : test-compile

check : test

mosq_test : ${TEST_OBJS} ${LIB_OBJS}
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

bridge_topic_test : ${BRIDGE_TOPIC_TEST_OBJS} ${BRIDGE_TOPIC_OBJS}
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

keepalive_test : ${KEEPALIVE_TEST_OBJS} ${KEEPALIVE_OBJS}
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

persist_read_test : ${PERSIST_READ_TEST_OBJS} ${PERSIST_READ_OBJS}
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

persist_write_test : ${PERSIST_WRITE_TEST_OBJS} ${PERSIST_WRITE_OBJS}
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

subs_test : ${SUBS_TEST_OBJS} ${SUBS_OBJS}
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

bridge_topic_test.o : bridge_topic_test.c
	${CROSS_COMPILE}${CC} -I${R}/src $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

broker_stubs.o : stubs.c
	${CROSS_COMPILE}${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

lib_stubs.o : stubs.c
	${CROSS_COMPILE}$(CC) $(LIB_CPPFLAGS) $(LIB_CFLAGS) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

persist_read_test.o : persist_read_test.c
	${CROSS_COMPILE}${CC} -I${R}/test $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

persist_read_stubs.o: persist_read_stubs.c
	${CROSS_COMPILE}${CC} -I${R}/src $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

persist_write_test.o : persist_write_test.c
	${CROSS_COMPILE}${CC} -I${R}/test $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

persist_write_stubs.o: persist_write_stubs.c
	${CROSS_COMPILE}${CC} -I${R}/src $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

subs_test.o : subs_test.c
	${CROSS_COMPILE}${CC} -I${R}/test $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

subs_stubs.o: subs_stubs.c
	${CROSS_COMPILE}${CC} -I${R}/src $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

${R}/src/bridge_topic.o : ${R}/src/bridge_topic.c
	$(MAKE) -C ${R}/src/ bridge_topic.o

${R}/src/database.o : ${R}/src/database.c
	$(MAKE) -C ${R}/src/ database.o

${R}/lib/memory_mosq.o : ${R}/lib/memory_mosq.c
	$(MAKE) -C ${R}/lib/ memory_mosq.o

${R}/src/memory_mosq.o : ${R}/lib/memory_mosq.c
	$(MAKE) -C ${R}/src/ memory_mosq.o

${R}/src/memory_public.o : ${R}/src/memory_public.c
	$(MAKE) -C ${R}/src/ memory_public.o

${R}/lib/misc_mosq.o : ${R}/common/misc_mosq.c ${R}/common/misc_mosq.h
	$(MAKE) -C ${R}/lib/ misc_mosq.o

${R}/src/misc_mosq.o : ${R}/common/misc_mosq.c ${R}/common/misc_mosq.h
	$(MAKE) -C ${R}/src/ misc_mosq.o

${R}/lib/packet_datatypes.o : ${R}/lib/packet_datatypes.c
	$(MAKE) -C ${R}/lib/ packet_datatypes.o

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

${R}/lib/property_mosq.o : ${R}/lib/property_mosq.c
	$(MAKE) -C ${R}/lib/ property_mosq.o

${R}/src/property_mosq.o : ${R}/lib/property_mosq.c
	$(MAKE) -C ${R}/src/ property_mosq.o

${R}/src/retain.o : ${R}/src/retain.c
	$(MAKE) -C ${R}/src/ retain.o

${R}/src/subs.o : ${R}/src/subs.c
	$(MAKE) -C ${R}/src/ subs.o

${R}/src/topic_tok.o : ${R}/src/topic_tok.c
	$(MAKE) -C ${R}/src/ topic_tok.o

${R}/lib/util_mosq.o : ${R}/lib/util_mosq.c
	$(MAKE) -C ${R}/lib/ util_mosq.o

${R}/src/util_mosq.o : ${R}/lib/util_mosq.c
	$(MAKE) -C ${R}/src/ util_mosq.o

${R}/lib/util_topic.o : ${R}/lib/util_topic.c
	$(MAKE) -C ${R}/lib/ util_topic.o

${R}/src/util_topic.o : ${R}/lib/util_topic.c
	$(MAKE) -C ${R}/src/ util_topic.o

${R}/lib/utf8_mosq.o : ${R}/lib/utf8_mosq.c
	$(MAKE) -C ${R}/lib/ utf8_mosq.o

${R}/src/utf8_mosq.o : ${R}/lib/utf8_mosq.c
	$(MAKE) -C ${R}/src/ utf8_mosq.o

build : mosq_test bridge_topic_test keepalive_test persist_read_test persist_write_test subs_test

test-lib : build
	./mosq_test

test-broker : build
	./bridge_topic_test
	./keepalive_test
	./persist_read_test
	./persist_write_test
	./subs_test

test : test-broker test-lib

test-compile: build

clean :
	-rm -rf mosq_test bridge_topic_test keepalive_test persist_read_test persist_write_test subs_test
	-rm -rf *.o *.gcda *.gcno coverage.info out/

coverage :
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory out
