.PHONY: all check test test-compile ptest clean

all :

check : test

test-compile:

test:
	./db-dump-client-stats.py
	./db-dump-corrupt.py
	./db-dump-json-v6-mqtt-v5-props.py
	./db-dump-print-empty.py
	./db-dump-print-v6-all.py
	./db-dump-print-v6-mqtt-v5-props.py
	./db-dump-stats.py
	./db-dump-stats-current.py

ptest:
	./test.py

clean :
