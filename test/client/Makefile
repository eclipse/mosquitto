R=../..
include ${R}/config.mk

.PHONY: all check test test-compile ptest clean
.NOTPARALLEL:

all :

check : test
test : 02 03 04
	./test.sh
	./test-ws.sh

test-compile:

02 :
	./02-subscribe-argv-errors-without-tls.py
ifeq ($(WITH_TLS),yes)
	./02-subscribe-argv-errors-tls.py
ifeq ($(WITH_TLS_PSK),yes)
	./02-subscribe-argv-errors-tls-psk.py
endif
endif
	./02-subscribe-env.py
	./02-subscribe-filter-out.py
	./02-subscribe-format.py
	./02-subscribe-format-json-qos0.py
	./02-subscribe-format-json-qos1.py
	./02-subscribe-format-json-properties.py
	./02-subscribe-format-json-retain.py
	./02-subscribe-qos1.py
ifeq ($(WITH_WEBSOCKETS),yes)
	./02-subscribe-qos1-ws.py
endif
	./02-subscribe-format.py
	./02-subscribe-null.py
	./02-subscribe-verbose.py

03 :
	./03-publish-argv-errors-without-tls.py
ifeq ($(WITH_TLS),yes)
	./03-publish-argv-errors-tls.py
ifeq ($(WITH_TLS_PSK),yes)
	./03-publish-argv-errors-tls-psk.py
endif
endif
	./03-publish-env.py
	./03-publish-file-empty.py
	./03-publish-file.py
	./03-publish-options-file.py
	./03-publish-qos0-empty.py
	./03-publish-qos1-properties.py
	./03-publish-qos1.py
ifeq ($(WITH_WEBSOCKETS),yes)
	./03-publish-qos1-ws.py
	./03-publish-qos1-ws-large.py
endif
	./03-publish-repeat.py
	./03-publish-socks.py
	./03-publish-stdin-file.py
	./03-publish-stdin-line.py
	./03-publish-url.py

04 :
	./04-rr-argv-errors-without-tls.py
ifeq ($(WITH_TLS),yes)
	./04-rr-argv-errors-tls.py
ifeq ($(WITH_TLS_PSK),yes)
	./04-rr-argv-errors-tls-psk.py
endif
endif
	./04-rr-env.py
	./04-rr-qos1.py
ifeq ($(WITH_WEBSOCKETS),yes)
	./04-rr-qos1-ws.py
endif

ptest :
	./test.sh
	./test-ws.sh
	./test.py

clean:
