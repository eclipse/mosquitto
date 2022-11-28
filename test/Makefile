R=..
include ${R}/config.mk

.PHONY: all check test test-compile ptest clean

all :

test-compile:
	$(MAKE) -C broker test-compile
	$(MAKE) -C client test-compile
	$(MAKE) -C lib test-compile
	$(MAKE) -C unit test-compile

check : test

test : utest
	$(MAKE) -C apps test
	$(MAKE) -C broker test
	$(MAKE) -C lib test
	$(MAKE) -C client test

ptest : utest
	$(MAKE) -C apps ptest
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
	$(MAKE) -C apps clean
