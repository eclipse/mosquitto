include ../../config.mk

.PHONY: all check test test-broker test-lib clean coverage

CPPFLAGS:=$(CPPFLAGS) -I../.. -I../../lib -I../../src
ifeq ($(WITH_BUNDLED_DEPS),yes)
        CPPFLAGS:=$(CPPFLAGS) -I../../src/deps
endif

CFLAGS:=$(CFLAGS) -coverage -Wall -ggdb
LDFLAGS:=$(LDFLAGS) -coverage
LDADD:=$(LDADD) -lcunit

TEST_OBJS = test.o \
			datatype_read.o \
			datatype_write.o \
			property_add.o \
			property_read.o \
			property_user_read.o \
			property_write.o \
			stubs.o \
			util_topic_test.o \
			utf8.o

LIB_OBJS = memory_mosq.o \
		   packet_datatypes.o \
		   property_mosq.o \
		   util_topic.o \
		   utf8_mosq.o

PERSIST_READ_TEST_OBJS = \
		persist_read_test.o \
		persist_read_stubs.o

PERSIST_READ_OBJS = \
		memory_mosq.o \
		packet_datatypes.o \
		persist_read.o \
		persist_read_v234.o \
		persist_read_v5.o \
		property_mosq.o \
		utf8_mosq.o \
		util_mosq.o

PERSIST_WRITE_TEST_OBJS = \
		persist_write_test.o \
		persist_write_stubs.o

PERSIST_WRITE_OBJS = \
		database.o \
		memory_mosq.o \
		packet_datatypes.o \
		persist_read.o \
		persist_read_v234.o \
		persist_read_v5.o \
		persist_write.o \
		persist_write_v5.o \
		property_mosq.o \
		subs.o \
		utf8_mosq.o \
		util_mosq.o

all : test

check : test

mosq_test : ${TEST_OBJS} ${LIB_OBJS}
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

persist_read_test : ${PERSIST_READ_TEST_OBJS} ${PERSIST_READ_OBJS}
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

persist_write_test : ${PERSIST_WRITE_TEST_OBJS} ${PERSIST_WRITE_OBJS}
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)


database.o : ../../src/database.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -DWITH_BROKER -DWITH_PERSISTENCE -c -o $@ $^

memory_mosq.o : ../../lib/memory_mosq.c
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

subs.o : ../../src/subs.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -DWITH_BROKER -DWITH_PERSISTENCE -c -o $@ $^

util_mosq.o : ../../lib/util_mosq.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

util_topic.o : ../../lib/util_topic.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

utf8_mosq.o : ../../lib/utf8_mosq.c
	$(CROSS_COMPILE)$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

test-lib : mosq_test
	./mosq_test

test-broker : persist_read_test persist_write_test
	./persist_read_test
	./persist_write_test

test : test-broker test-lib

clean : 
	-rm -rf mosq_test persist_read_test persist_write_test
	-rm -rf *.o *.gcda *.gcno coverage.info out/

coverage :
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory out
