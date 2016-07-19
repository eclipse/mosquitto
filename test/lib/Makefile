include ../../config.mk

.PHONY: all test test-compile test-compile-c test-compile-cpp c cpp
.NOTPARALLEL:

LD_LIBRARY_PATH=../../lib

all :

test : c cpp

test-compile : test-compile-c test-compile-cpp

test-compile-c : 
	$(MAKE) -C c

test-compile-cpp : 
	$(MAKE) -C cpp

c cpp : test-compile
	./01-con-discon-success.py $@/01-con-discon-success.test
	./01-will-set.py $@/01-will-set.test
	./01-unpwd-set.py $@/01-unpwd-set.test
	./01-will-unpwd-set.py $@/01-will-unpwd-set.test
	./01-no-clean-session.py $@/01-no-clean-session.test
	./01-keepalive-pingreq.py $@/01-keepalive-pingreq.test
	./02-subscribe-qos0.py $@/02-subscribe-qos0.test
	./02-subscribe-qos1.py $@/02-subscribe-qos1.test
	./02-subscribe-qos2.py $@/02-subscribe-qos2.test
	./02-unsubscribe.py $@/02-unsubscribe.test
	./03-publish-qos0.py $@/03-publish-qos0.test
	./03-publish-qos0-no-payload.py $@/03-publish-qos0-no-payload.test
	./03-publish-c2b-qos1-disconnect.py $@/03-publish-c2b-qos1-disconnect.test
	./03-publish-c2b-qos2.py $@/03-publish-c2b-qos2.test
	./03-publish-c2b-qos2-disconnect.py $@/03-publish-c2b-qos2-disconnect.test
	./03-publish-b2c-qos1.py $@/03-publish-b2c-qos1.test
	./03-publish-b2c-qos2.py $@/03-publish-b2c-qos2.test
	./04-retain-qos0.py $@/04-retain-qos0.test
ifeq ($(WITH_TLS),yes)
	./08-ssl-connect-no-auth.py $@/08-ssl-connect-no-auth.test
	./08-ssl-connect-cert-auth.py $@/08-ssl-connect-cert-auth.test
	./08-ssl-connect-cert-auth-enc.py $@/08-ssl-connect-cert-auth-enc.test
	./08-ssl-bad-cacert.py $@/08-ssl-bad-cacert.test
	#./08-ssl-fake-cacert.py $@/08-ssl-fake-cacert.test
endif
	./09-util-topic-matching.py $@/09-util-topic-matching.test
	./09-util-topic-tokenise.py $@/09-util-topic-tokenise.test
	./09-util-utf8-validate.py $@/09-util-utf8-validate.test

clean : 
	$(MAKE) -C c clean
	$(MAKE) -C cpp clean
