include ../../config.mk

.PHONY: all clean test ptest
.NOTPARALLEL:

all :

clean : 
	-rm -f *.vglog
	$(MAKE) -C c clean

test-compile : 
	$(MAKE) -C c

ptest : test-compile
	./ptest.py

test : test-compile 01 02 03 04 05 06 07 08 09 10 11

01 :
	./01-connect-success.py
	./01-connect-invalid-protonum.py
	./01-connect-invalid-id-0.py
	./01-connect-invalid-id-0-311.py
	./01-connect-invalid-id-missing.py
	./01-connect-invalid-reserved.py
	./01-connect-invalid-id-utf8.py
	./01-connect-anon-denied.py
	./01-connect-uname-no-password-denied.py
	./01-connect-uname-password-denied.py
ifeq ($(WITH_TLS),yes)
	./01-connect-uname-password-success.py
else
	./01-connect-uname-password-success-no-tls.py
endif
	./01-connect-uname-no-flag.py
	./01-connect-uname-pwd-no-flag.py
	./01-connect-uname-invalid-utf8.py


02 :
	./02-subscribe-qos0.py
	./02-subscribe-qos1.py
	./02-subscribe-qos2.py
	./02-subpub-qos0.py
	./02-subpub-qos1.py
	./02-subpub-qos2.py
	./02-unsubscribe-qos0.py
	./02-unsubscribe-qos1.py
	./02-unsubscribe-qos2.py
	./02-unsubscribe-invalid-no-topic.py
	./02-subscribe-invalid-utf8.py

03 :
	./03-publish-qos1.py
	./03-publish-qos2.py
	./03-publish-b2c-disconnect-qos1.py
	./03-publish-c2b-disconnect-qos2.py
	./03-publish-b2c-disconnect-qos2.py
	./03-pattern-matching.py
	./03-publish-qos1-queued-bytes.py
	./03-publish-invalid-utf8.py

04 :
	./04-retain-qos0.py
	./04-retain-qos0-fresh.py
	./04-retain-qos0-repeated.py
	./04-retain-qos1-qos0.py
	./04-retain-qos0-clear.py
	./04-retain-upgrade-outgoing-qos.py

05 :
	./05-clean-session-qos1.py 

06 :
	./06-bridge-reconnect-local-out.py
	./06-bridge-br2b-disconnect-qos1.py
	./06-bridge-br2b-disconnect-qos2.py
	./06-bridge-b2br-disconnect-qos1.py
	./06-bridge-b2br-disconnect-qos2.py
	./06-bridge-fail-persist-resend-qos1.py
	./06-bridge-fail-persist-resend-qos2.py
	./06-bridge-b2br-remapping.py
	./06-bridge-br2b-remapping.py
	./06-bridge-per-listener-settings.py

07 :
	./07-will-qos0.py
	./07-will-null.py
	./07-will-null-topic.py
	./07-will-invalid-utf8.py
	./07-will-no-flag.py

08 :
ifeq ($(WITH_TLS),yes)
	./08-ssl-connect-no-auth.py
	./08-ssl-connect-no-auth-wrong-ca.py
	./08-ssl-connect-cert-auth.py
	./08-ssl-connect-cert-auth-without.py
	./08-ssl-connect-cert-auth-expired.py
	./08-ssl-connect-cert-auth-revoked.py
	./08-ssl-connect-cert-auth-crl.py
	./08-ssl-connect-identity.py
	./08-ssl-connect-no-identity.py
	./08-ssl-bridge.py
ifeq ($(WITH_TLS_PSK),yes)
	./08-tls-psk-pub.py
	./08-tls-psk-bridge.py
endif
endif

09 :
	./09-plugin-auth-unpwd-success.py
	./09-plugin-auth-unpwd-fail.py
	./09-plugin-auth-acl-sub.py
	./09-plugin-auth-v2-unpwd-success.py
	./09-plugin-auth-v2-unpwd-fail.py
	./09-plugin-auth-defer-unpwd-success.py
	./09-plugin-auth-defer-unpwd-fail.py

10 :
	./10-listener-mount-point.py

11 :
	./11-persistent-subscription.py
