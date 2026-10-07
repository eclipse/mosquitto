R=../..
include ${R}/config.mk

.PHONY: all check test-compile test clean

LOCAL_CPPFLAGS+= \
	-DWITH_THREADING \
	-DWITH_TLS \
	-I../ \
	-I${R}/include \
	-I${R} \
	-I${R}/lib \
	-I${R}/test/mock

LOCAL_CXXFLAGS+=-std=c++20 -Wall -ggdb -D TEST_SOURCE_DIR='"$(realpath .)"'

MOCKS = \
	pthread_mock.o

ifeq ($(WITH_EDITLINE),yes)
MOCKS+=editline_mock.o
endif

all : test-compile
test-compile : ${MOCKS}
	$(MAKE) -C apps/mosquitto_ctrl test-compile
	$(MAKE) -C lib test-compile

check : test
test :

${MOCKS} : %.o: %.cpp
	$(CROSS_COMPILE)$(CXX) $(LOCAL_CPPFLAGS) $(LOCAL_CXXFLAGS) -c $< -o $@


clean :
	-rm -rf *.o *.gcda *.gcno coverage.info out/

coverage :
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory out

install:
uninstall:
