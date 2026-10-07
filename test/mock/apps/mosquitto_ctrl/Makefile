R=../../../..
include ${R}/config.mk

.PHONY: all check test-compile test clean

LOCAL_CPPFLAGS+= \
	-DWITH_CTRL_SHELL \
	-DWITH_EDITLINE \
	-I../ \
	-I${R} \
	-I${R}/apps/mosquitto_ctrl \
	-I${R}/include \
	-I${R}/lib \
	-I${R}/test/mock

LOCAL_CXXFLAGS+=-std=c++20 -Wall -ggdb -D TEST_SOURCE_DIR='"$(realpath .)"'

MOCK_OBJS = \
	ctrl_shell_mock.o

ifeq ($(WITH_EDITLINE),yes)
all : test-compile
test-compile: ${MOCK_OBJS}
check : test
else
all :
test-compile:
check :
endif


# MOCKS

${MOCK_OBJS} : %.o: %.cpp ctrl_shell_mock.hpp
	$(CROSS_COMPILE)$(CXX) $(LOCAL_CPPFLAGS) $(LOCAL_CXXFLAGS) -c $< -o $@

clean :
	-rm -rf *.o *.gcda *.gcno

install:

uninstall:
