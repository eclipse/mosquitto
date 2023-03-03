R=../../..
include ${R}/config.mk

.PHONY: all check test ptest clean
.NOTPARALLEL:

all :

check : test

test : 
	./passwd-args.py
	./passwd-changes.py

ptest :
	./test.py

clean:
