include ../../config.mk

.PHONY: all check test test-broker test-lib clean coverage

CPPFLAGS:=$(CPPFLAGS) -I../.. -I../../include -I../../lib -I../../src
ifeq ($(WITH_BUNDLED_DEPS),yes)
        CPPFLAGS:=$(CPPFLAGS) -I../../deps
endif

CFLAGS:=$(CFLAGS) -coverage -Wall -ggdb
LDFLAGS:=$(LDFLAGS) -coverage
LDADD:=$(LDADD) -lcunit

TEST_OBJS = test.o \
			datatype_read.o \
			datatype_write.o \
			misc_trim_test.o \
			property_add.o \
			property_read.o \
			property_user_read.o \
			property_write.o \
			stubs.o \
			util_topic_test.o \
			utf8.o

LIB_OBJS = memory_mosq.o \
		   memory_public.o \
		   misc_mosq.o \
		   packet_datatypes.o \
		   property_mosq.o \
		   util_mosq.o \
		   util_topic.o \
		   utf8_mosq.o

BRIDGE_TOPIC_TEST_OBJS = \
		bridge_topic_test.o \
		stubs.o \

BRIDGE_TOPIC_OBJS = \
		bridge_topic.o \
		memory_mosq.o \
		memory_public.o \
		util_topic.o \

PERSIST_READ_TEST_OBJS = \
		persist_read_test.o \
		persist_read_stubs.o

PERSIST_READ_OBJS = \
		memory_mosq.o \
		memory_public.o \
		misc_mosq.o \
		packet_datatypes.o \
		persist_read.o \
		persist_read_v234.o \
		persist_read_v5.o \
		property_mosq.o \
		retain.o \
		topic_tok.o \
		utf8_mosq.o \
		util_mosq.o

PERSIST_WRITE_TEST_OBJS = \
		persist_write_test.o \
		persist_write_stubs.o

PERSIST_WRITE_OBJS = \
		database.o \
		memory_mosq.o \
		memory_public.o \
		misc_mosq.o \
		packet_datatypes.o \
		persist_read.o \
		persist_read_v234.o \
		persist_read_v5.o \
		persist_write.o \
		persist_write_v5.o \
		property_mosq.o \
		retain.o \
		subs.o \
		topic_tok.o \
		utf8_mosq.o \
		util_mosq.o

SUBS_TEST_OBJS = \
		subs_test.o \
		subs_stubs.o

SUBS_OBJS = \
		database.o \
		memory_mosq.o \
		memory_public.o \
		subs.o \
		topic_tok.o

all : test

check : test

mosq_test : ${TEST_OBJS} ${LIB_OBJS}
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

bridge_topic_test : ${BRIDGE_TOPIC_TEST_OBJS} ${BRIDGE_TOPIC_OBJS}
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

persist_read_test : ${PERSIST_READ_TEST_OBJS} ${PERSIST_READ_OBJS}
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

persist_write_test : ${PERSIST_WRITE_TEST_OBJS} ${PERSIST_WRITE_OBJS}
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

subs_test : ${SUBS_TEST_OBJS} ${SUBS_OBJS}
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)


bridge_topic.o : ../../src/bridge_topic.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -DWITH_BROKER -DWITH_BRIDGE -c -o $@ $^

database.o : ../../src/database.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -DWITH_BROKER -DWITH_PERSISTENCE -c -o $@ $^

memory_mosq.o : ../../lib/memory_mosq.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

memory_public.o : ../../src/memory_public.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

misc_mosq.o : ../../lib/misc_mosq.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

packet_datatypes.o : ../../lib/packet_datatypes.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

persist_read.o : ../../src/persist_read.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -DWITH_BROKER -DWITH_PERSISTENCE -c -o $@ $^

persist_read_v234.o : ../../src/persist_read_v234.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -DWITH_BROKER -DWITH_PERSISTENCE -c -o $@ $^

persist_read_v5.o : ../../src/persist_read_v5.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -DWITH_BROKER -DWITH_PERSISTENCE -c -o $@ $^

persist_write.o : ../../src/persist_write.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -DWITH_BROKER -DWITH_PERSISTENCE -c -o $@ $^

persist_write_v5.o : ../../src/persist_write_v5.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -DWITH_BROKER -DWITH_PERSISTENCE -c -o $@ $^

property_mosq.o : ../../lib/property_mosq.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

retain.o : ../../src/retain.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -DWITH_BROKER -DWITH_PERSISTENCE -c -o $@ $^

subs.o : ../../src/subs.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -DWITH_BROKER -DWITH_PERSISTENCE -c -o $@ $^

topic_tok.o : ../../src/topic_tok.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -DWITH_BROKER -DWITH_PERSISTENCE -c -o $@ $^

util_mosq.o : ../../lib/util_mosq.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

util_topic.o : ../../lib/util_topic.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

utf8_mosq.o : ../../lib/utf8_mosq.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

build : mosq_test bridge_topic_test persist_read_test persist_write_test subs_test

test-lib : build
	./mosq_test

test-broker : build
	./bridge_topic_test
	./persist_read_test
	./persist_write_test
	./subs_test

test : test-broker test-lib

clean : 
	-rm -rf mosq_test bridge_topic_test persist_read_test persist_write_test
	-rm -rf *.o *.gcda *.gcno coverage.info out/

coverage :
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory out
