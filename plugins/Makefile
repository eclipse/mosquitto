R=..
include ${R}/config.mk

DIRS= \
		acl-file \
		dynamic-security \
		examples \
		password-file \
		sparkplug-aware

ifeq ($(WITH_SQLITE),yes)
DIRS+=persist-sqlite
endif

.PHONY : all binary check clean reallyclean test test-compile install uninstall

all :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d}; done

binary :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done

clean :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done

reallyclean :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done

test-compile :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done

check : test
test :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done

install :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done

uninstall :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done
