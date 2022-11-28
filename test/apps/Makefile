R=../..
include ${R}/config.mk

.PHONY: all check test ptest clean
.NOTPARALLEL:

all :

check : test

test :
	$(MAKE) -C db_dump test
	$(MAKE) -C ctrl test
	$(MAKE) -C passwd test

ptest :
	$(MAKE) -C db_dump ptest
	$(MAKE) -C ctrl ptest
	$(MAKE) -C passwd ptest

reallyclean : clean
clean :
	$(MAKE) -C db_dump clean
