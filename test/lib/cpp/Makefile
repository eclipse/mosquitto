.PHONY: all test 01 02 03 04 08 09 clean reallyclean

CFLAGS=-I../../../include -I../../../lib/cpp -DDEBUG
LIBS=../../../lib/libmosquitto.so.1 ../../../lib/cpp/libmosquittopp.so.1

all : 01 02 03 04 08 09

01-con-discon-success.test : 01-con-discon-success.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

01-will-set.test : 01-will-set.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

01-unpwd-set.test : 01-unpwd-set.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

01-will-unpwd-set.test : 01-will-unpwd-set.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

01-no-clean-session.test : 01-no-clean-session.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

01-keepalive-pingreq.test : 01-keepalive-pingreq.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

02-subscribe-qos0.test : 02-subscribe-qos0.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

02-subscribe-qos1.test : 02-subscribe-qos1.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

02-subscribe-qos2.test : 02-subscribe-qos2.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

02-unsubscribe.test : 02-unsubscribe.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

03-publish-qos0.test : 03-publish-qos0.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

03-publish-qos0-no-payload.test : 03-publish-qos0-no-payload.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

03-publish-c2b-qos1-disconnect.test : 03-publish-c2b-qos1-disconnect.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

03-publish-c2b-qos2.test : 03-publish-c2b-qos2.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

03-publish-c2b-qos2-disconnect.test : 03-publish-c2b-qos2-disconnect.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

03-publish-b2c-qos1.test : 03-publish-b2c-qos1.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

03-publish-b2c-qos2.test : 03-publish-b2c-qos2.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

04-retain-qos0.test : 04-retain-qos0.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

08-ssl-connect-no-auth.test : 08-ssl-connect-no-auth.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

08-ssl-connect-cert-auth.test : 08-ssl-connect-cert-auth.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

08-ssl-connect-cert-auth-enc.test : 08-ssl-connect-cert-auth-enc.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

08-ssl-bad-cacert.test : 08-ssl-bad-cacert.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

08-ssl-fake-cacert.test : 08-ssl-fake-cacert.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

09-util-topic-tokenise.test : 09-util-topic-tokenise.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(LIBS)

01 : 01-con-discon-success.test 01-will-set.test 01-unpwd-set.test 01-will-unpwd-set.test 01-no-clean-session.test 01-keepalive-pingreq.test

02 : 02-subscribe-qos0.test 02-subscribe-qos1.test 02-subscribe-qos2.test 02-unsubscribe.test

03 : 03-publish-qos0.test 03-publish-qos0-no-payload.test 03-publish-c2b-qos1-disconnect.test 03-publish-c2b-qos2.test 03-publish-c2b-qos2-disconnect.test 03-publish-b2c-qos1.test 03-publish-b2c-qos2.test

04 : 04-retain-qos0.test

08 : 08-ssl-connect-no-auth.test 08-ssl-connect-cert-auth.test 08-ssl-connect-cert-auth-enc.test 08-ssl-bad-cacert.test 08-ssl-fake-cacert.test

09 : 09-util-topic-tokenise.test

reallyclean : clean
	-rm -f *.orig

clean :
	rm -f *.test
