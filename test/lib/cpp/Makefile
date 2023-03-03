R=../../..
include ${R}/config.mk

.PHONY: all test clean reallyclean

LOCAL_CXXFLAGS=${CXXFLAGS} -I${R}/include -I${R}/test -I${R}/lib/cpp -DDEBUG -Werror -W
LIBS=${R}/lib/libmosquitto.so.1 ${R}/lib/cpp/libmosquittopp.so.1

SRC = \
	01-con-discon-success.cpp \
	01-con-discon-success-v5.cpp \
	01-con-discon-will-clear.cpp \
	01-con-discon-will-v5.cpp \
	01-con-discon-will.cpp \
	01-keepalive-pingreq.cpp \
	01-no-clean-session.cpp \
	01-pre-connect-callback.cpp \
	01-server-keepalive-pingreq.cpp \
	01-unpwd-set.cpp \
	01-will-set.cpp \
	01-will-unpwd-set.cpp \
	02-subscribe-helper-callback-qos2.cpp \
	02-subscribe-helper-simple-qos2.cpp \
	02-subscribe-qos0.cpp \
	02-subscribe-qos1-async1.cpp \
	02-subscribe-qos1-async2.cpp \
	02-subscribe-qos1.cpp \
	02-subscribe-qos2.cpp \
	02-unsubscribe.cpp \
	02-unsubscribe-v5.cpp \
	03-publish-b2c-qos1.cpp \
	03-publish-b2c-qos1-unexpected-puback.cpp \
	03-publish-b2c-qos2.cpp \
	03-publish-b2c-qos2-len.cpp \
	03-publish-b2c-qos2-unexpected-pubcomp.cpp \
	03-publish-b2c-qos2-unexpected-pubrel.cpp \
	03-publish-c2b-qos1-disconnect.cpp \
	03-publish-c2b-qos1-len.cpp \
	03-publish-c2b-qos1-receive-maximum.cpp \
	03-publish-c2b-qos2-disconnect.cpp \
	03-publish-c2b-qos2.cpp \
	03-publish-c2b-qos2-len.cpp \
	03-publish-c2b-qos2-maximum-qos-0.cpp \
	03-publish-c2b-qos2-maximum-qos-1.cpp \
	03-publish-c2b-qos2-pubrec-error.cpp \
	03-publish-c2b-qos2-receive-maximum.cpp \
	03-publish-loop.cpp \
	03-publish-loop-forever.cpp \
	03-publish-loop-manual.cpp \
	03-publish-loop-start.cpp \
	03-publish-qos0-no-payload.cpp \
	03-publish-qos0.cpp \
	03-request-response-1.cpp \
	03-request-response-2.cpp \
	03-request-response-correlation-1.cpp \
	04-retain-qos0.cpp \
	08-ssl-bad-cacert.cpp \
	08-ssl-connect-cert-auth-enc.cpp \
	08-ssl-connect-cert-auth.cpp \
	08-ssl-connect-cert-auth-custom-ssl-ctx.cpp \
	08-ssl-connect-cert-auth-custom-ssl-ctx-default.cpp \
	08-ssl-connect-no-auth.cpp \
	08-ssl-connect-san.cpp \
	08-ssl-fake-cacert.cpp \
	09-util-topic-tokenise.cpp \
	11-prop-oversize-packet.cpp \
	11-prop-send-content-type.cpp \
	11-prop-send-payload-format.cpp \
	11-prop-recv.cpp


LIBS += -lssl -lcrypto

TESTS = ${SRC:.cpp=.test}

all : ${TESTS}

${TESTS} : %.test: %.cpp ${R}/test/path_helper.h
	$(CXX) -DTEST_SOURCE_DIR='"$(realpath .)"' $< -o $@ $(LOCAL_CXXFLAGS) $(LIBS)

reallyclean : clean
	-rm -f *.orig

clean :
	rm -f *.test
