R=../..
include ${R}/config.mk

.PHONY: all check test test-compile test-compile-c test-compile-cpp
.NOTPARALLEL:

LD_LIBRARY_PATH=${R}/lib

all :

check : test

ptest : test-compile msg_sequence_test
	./test.py

msg_sequence_test: test-compile-c
	./msg_sequence_test.py

test-compile : test-compile-c test-compile-cpp

test-compile-c :
	$(MAKE) -C c

test-compile-cpp :
	$(MAKE) -C cpp

test : test-compile
	./01-con-discon-success.py
	./01-con-discon-success-v5.py
	./01-con-discon-will.py
	./01-con-discon-will-v5.py
	./01-con-discon-will-clear.py
	./01-keepalive-pingreq.py
	./01-no-clean-session.py
	./01-server-keepalive-pingreq.py
	./01-pre-connect-callback.py
	./01-unpwd-set.py
	./01-will-set.py
	./01-will-unpwd-set.py
	./02-subscribe-qos0.py
	./02-subscribe-qos1.py
	./02-subscribe-qos2.py
	./02-subscribe-helper-qos2.py
	./02-unsubscribe-multiple-v5.py
	./02-unsubscribe-v5.py
	./02-unsubscribe.py
	./03-publish-b2c-qos1.py
	./03-publish-b2c-qos1-unexpected-puback.py
	./03-publish-b2c-qos2-len.py
	./03-publish-b2c-qos2.py
	./03-publish-b2c-qos2-unexpected-pubrel.py
	./03-publish-b2c-qos2-unexpected-pubcomp.py
	./03-publish-c2b-qos1-disconnect.py
	./03-publish-c2b-qos1-len.py
	./03-publish-c2b-qos1-receive-maximum.py
	./03-publish-c2b-qos2-disconnect.py
	./03-publish-c2b-qos2-len.py
	./03-publish-c2b-qos2-maximum-qos-0.py
	./03-publish-c2b-qos2-maximum-qos-1.py
	./03-publish-c2b-qos2-pubrec-error.py
	./03-publish-c2b-qos2-receive-maximum-1.py
	./03-publish-c2b-qos2-receive-maximum-2.py
	./03-publish-c2b-qos2.py
	./03-publish-loop.py
	./03-publish-qos0-no-payload.py
	./03-publish-qos0.py
	./03-request-response-correlation.py
	./03-request-response.py
	./04-retain-qos0.py
ifeq ($(WITH_TLS),yes)
	./08-ssl-fake-cacert.py
	./08-ssl-bad-cacert.py
	./08-ssl-connect-cert-auth-enc.py
	./08-ssl-connect-cert-auth.py
	./08-ssl-connect-no-auth.py
	./08-ssl-connect-san.py
endif
	./09-util-topic-tokenise.py
	./11-prop-oversize-packet.py
	./11-prop-send-content-type.py
	./11-prop-send-payload-format.py
	./11-prop-recv-qos0.py
	./11-prop-recv-qos1.py
	./11-prop-recv-qos2.py

clean :
	$(MAKE) -C c clean
	$(MAKE) -C cpp clean
