.PHONY: all test 01 02 03 04 08 09 clean reallyclean

CFLAGS=-I../../../lib -Werror
LIBS=../../../lib/libmosquitto.so.1

all : 01 02 03 04 08 09

01-con-discon-success.test : 01-con-discon-success.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

01-will-set.test : 01-will-set.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

01-unpwd-set.test : 01-unpwd-set.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

01-will-unpwd-set.test : 01-will-unpwd-set.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

01-no-clean-session.test : 01-no-clean-session.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

01-keepalive-pingreq.test : 01-keepalive-pingreq.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

02-subscribe-qos0.test : 02-subscribe-qos0.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

02-subscribe-qos1.test : 02-subscribe-qos1.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

02-subscribe-qos2.test : 02-subscribe-qos2.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

02-unsubscribe.test : 02-unsubscribe.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

03-publish-qos0.test : 03-publish-qos0.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

03-publish-qos0-no-payload.test : 03-publish-qos0-no-payload.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

03-publish-c2b-qos1-disconnect.test : 03-publish-c2b-qos1-disconnect.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

03-publish-c2b-qos2.test : 03-publish-c2b-qos2.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

03-publish-c2b-qos2-disconnect.test : 03-publish-c2b-qos2-disconnect.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

03-publish-b2c-qos1.test : 03-publish-b2c-qos1.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

03-publish-b2c-qos2.test : 03-publish-b2c-qos2.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

04-retain-qos0.test : 04-retain-qos0.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

08-ssl-connect-no-auth.test : 08-ssl-connect-no-auth.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

08-ssl-connect-cert-auth.test : 08-ssl-connect-cert-auth.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

08-ssl-connect-cert-auth-enc.test : 08-ssl-connect-cert-auth-enc.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

08-ssl-bad-cacert.test : 08-ssl-bad-cacert.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

08-ssl-fake-cacert.test : 08-ssl-fake-cacert.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

09-util-topic-matching.test : 09-util-topic-matching.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

09-util-topic-tokenise.test : 09-util-topic-tokenise.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

09-util-utf8-validate.test : 09-util-utf8-validate.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

01 : 01-con-discon-success.test 01-will-set.test 01-unpwd-set.test 01-will-unpwd-set.test 01-no-clean-session.test 01-keepalive-pingreq.test

02 : 02-subscribe-qos0.test 02-subscribe-qos1.test 02-subscribe-qos2.test 02-unsubscribe.test

03 : 03-publish-qos0.test 03-publish-qos0-no-payload.test 03-publish-c2b-qos1-disconnect.test 03-publish-c2b-qos2.test 03-publish-c2b-qos2-disconnect.test 03-publish-b2c-qos1.test 03-publish-b2c-qos2.test

04 : 04-retain-qos0.test

08 : 08-ssl-connect-no-auth.test 08-ssl-connect-cert-auth.test 08-ssl-connect-cert-auth-enc.test 08-ssl-bad-cacert.test 08-ssl-fake-cacert.test

09 : 09-util-topic-matching.test 09-util-topic-tokenise.test 09-util-utf8-validate.test

reallyclean : clean
	-rm -f *.orig

clean :
	rm -f *.test
