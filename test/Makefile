include ../config.mk

.PHONY: all check test ptest clean fuzz

all :

check : test

test : utest
	$(MAKE) -C broker test
	$(MAKE) -C lib test
	$(MAKE) -C client test

ptest : utest
	$(MAKE) -C broker ptest
	$(MAKE) -C lib ptest
	$(MAKE) -C client test

utest :
	$(MAKE) -C unit test

fuzz :
	$(MAKE) -C fuzz fuzz

reallyclean : clean
clean :
	$(MAKE) -C lib clean
	$(MAKE) -C broker clean
	$(MAKE) -C unit clean
	$(MAKE) -C fuzz clean
