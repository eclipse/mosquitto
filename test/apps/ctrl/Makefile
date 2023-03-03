R=../../..
include ${R}/config.mk

.PHONY: all check test ptest clean
.NOTPARALLEL:

all :

check : test

test : 
	./ctrl-args.py
	./ctrl-broker.py
	./ctrl-dynsec.py

ptest:
	./test.py

clean:
