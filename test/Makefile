R=..
include ${R}/config.mk

.PHONY: all check test ptest clean

all :

check : test

test : utest
	$(MAKE) -C broker test
	$(MAKE) -C lib test
	$(MAKE) -C client test

ptest : utest
	$(MAKE) -C broker ptest
	$(MAKE) -C lib ptest
	$(MAKE) -C client ptest

utest :
	$(MAKE) -C unit test

reallyclean : clean
clean :
	$(MAKE) -C lib clean
	$(MAKE) -C broker clean
	$(MAKE) -C unit clean
