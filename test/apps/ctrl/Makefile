R=../../..
include ${R}/config.mk

.PHONY: all check test-compile test test-mock test-lib clean

LOCAL_CPPFLAGS+= \
	-DWITH_THREADING \
	-DWITH_TLS \
	-I../ \
	-I${R}/include \
	-I${R} \
	-I${R}/apps/mosquitto_ctrl \
	-I${R}/lib \
	-I${R}/test/mock \
	-I${R}/test/mock/apps/mosquitto_ctrl \
	-I${R}/test/mock/lib

LOCAL_CXXFLAGS+=-std=c++20 -Wall -ggdb -D TEST_SOURCE_DIR='"$(realpath .)"'
LOCAL_LDFLAGS+=
LOCAL_LIBADD+=-lcjson -lgmock -lgtest_main -lgtest ${R}/libcommon/libmosquitto_common.a

CTRL_OBJS = \
	${R}/apps/mosquitto_ctrl/ctrl_shell_broker.o \
	${R}/apps/mosquitto_ctrl/ctrl_shell.o \
	${R}/apps/mosquitto_ctrl/ctrl_shell_client.o \
	${R}/apps/mosquitto_ctrl/ctrl_shell_completion_tree.o \
	${R}/apps/mosquitto_ctrl/ctrl_shell_dynsec.o \
	${R}/apps/mosquitto_ctrl/ctrl_shell_post_connect.o \
	${R}/apps/mosquitto_ctrl/ctrl_shell_pre_connect.o \
	${R}/apps/mosquitto_ctrl/ctrl_shell_printf.o

LIBMOSQ_MOCKS = \
	${R}/test/mock/lib/libmosquitto_mock.o \
	${R}/test/mock/lib/actions_publish_mock.o \
	${R}/test/mock/lib/actions_subscribe_mock.o \
	${R}/test/mock/lib/callbacks_mock.o \
	${R}/test/mock/lib/connect_mock.o \
	${R}/test/mock/lib/loop_mock.o \
	${R}/test/mock/lib/options_mock.o \
	${R}/test/mock/lib/thread_mosq_mock.o

LIB_OBJS = \
	${CTRL_OBJS} \
	${R}/common/json_help.o \
	${R}/test/mock/apps/mosquitto_ctrl/ctrl_shell_mock.o \
	${R}/test/mock/editline_mock.o \
	${R}/test/mock/pthread_mock.o \
	${LIBMOSQ_MOCKS}

COMPLETION_OBJS = \
	${CTRL_OBJS} \
	${R}/common/json_help.o \
	${R}/test/mock/apps/mosquitto_ctrl/ctrl_shell_mock.o \
	${R}/test/mock/pthread_mock.o \
	${LIBMOSQ_MOCKS}

TEST_OBJS = \
	ctrl_shell_test.o \
	ctrl_shell_broker_test.o \
	ctrl_shell_completion_test.o \
	ctrl_shell_dynsec_test.o \
	ctrl_shell_help_test.o \
	ctrl_shell_options_test.o \
	ctrl_shell_pre_connect_test.o

ifeq ($(WITH_GMOCK),yes)
ifeq ($(WITH_EDITLINE),yes)
LOCAL_CPPFLAGS+=-DWITH_CTRL_SHELL -DWITH_EDITLINE
MOCK_TESTS = \
	ctrl_shell_test \
	ctrl_shell_broker_test \
	ctrl_shell_completion_test \
	ctrl_shell_dynsec_test \
	ctrl_shell_help_test \
	ctrl_shell_options_test \
	ctrl_shell_pre_connect_test
else
MOCK_TESTS =
endif
else
MOCK_TESTS =
endif

all : test-compile

check : test

# DEPS

${LIBMOSQ_MOCKS}:
	$(MAKE) -C ${R}/lib

${CTRL_OBJS} :
	$(MAKE) -C ${R}/apps/mosquitto_ctrl

${R}/common/json_help.o : ${R}/common/json_help.c ${R}/common/json_help.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

# MOCKS

${R}/test/mock/apps/mosquitto_ctrl/ctrl_shell_mock.o : ${R}/test/mock/apps/mosquitto_ctrl/ctrl_shell_mock.cpp ${R}/test/mock/apps/mosquitto_ctrl/ctrl_shell_mock.hpp
	$(MAKE) -C ${R}/test/mock/apps/mosquitto_ctrl test-compile

${R}/test/mock/editline_mock.o : ${R}/test/mock/editline_mock.cpp ${R}/test/mock/editline_mock.hpp
	$(MAKE) -C ${R}/test/mock test-compile

${R}/test/mock/pthread_mock.o : ${R}/test/mock/pthread_mock.cpp ${R}/test/mock/pthread_mock.hpp
	$(MAKE) -C ${R}/test/mock test-compile

# TESTS

${TEST_OBJS} : %.o: %.cpp
	$(CROSS_COMPILE)$(CXX) $(LOCAL_CPPFLAGS) $(LOCAL_CXXFLAGS) -c $< -o $@

ctrl_shell_test : ctrl_shell_test.o ${LIB_OBJS}
	$(CROSS_COMPILE)$(CXX) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LIBADD)

ctrl_shell_broker_test : ctrl_shell_broker_test.o ${LIB_OBJS}
	$(CROSS_COMPILE)$(CXX) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LIBADD)

ctrl_shell_completion_test : ctrl_shell_completion_test.o ${COMPLETION_OBJS}
	$(CROSS_COMPILE)$(CXX) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LIBADD) -ledit

ctrl_shell_dynsec_test : ctrl_shell_dynsec_test.o ${LIB_OBJS}
	$(CROSS_COMPILE)$(CXX) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LIBADD)

ctrl_shell_help_test : ctrl_shell_help_test.o ${LIB_OBJS}
	$(CROSS_COMPILE)$(CXX) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LIBADD)

ctrl_shell_options_test : ctrl_shell_options_test.o ${LIB_OBJS}
	$(CROSS_COMPILE)$(CXX) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LIBADD)

ctrl_shell_pre_connect_test : ctrl_shell_pre_connect_test.o ${LIB_OBJS}
	$(CROSS_COMPILE)$(CXX) $(LOCAL_CPPFLAGS) $(LOCAL_LDFLAGS) -o $@ $^ $(LOCAL_LIBADD)


test-compile : $(MOCK_TESTS)

test-mock : $(MOCK_TESTS)
ifeq ($(WITH_GMOCK),yes)
ifeq ($(WITH_EDITLINE),yes)
	./ctrl_shell_broker_test
	./ctrl_shell_completion_test
	./ctrl_shell_dynsec_test
	./ctrl_shell_help_test
	./ctrl_shell_options_test
	./ctrl_shell_pre_connect_test
	./ctrl_shell_test
endif
endif

test : test-mock
	./ctrl-args.py
	./ctrl-broker.py
	./ctrl-dynsec.py

ptest: test-mock
	./test.py

clean :
	-rm -rf $(MOCK_TESTS)
	-rm -rf *.o *.gcda *.gcno coverage.info out/

coverage :
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory out

install:

uninstall:
