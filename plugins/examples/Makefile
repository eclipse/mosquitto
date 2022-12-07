DIRS= \
		add-properties \
		auth-by-ip \
		client-lifetime-stats \
		client-properties \
		connection-state \
		delayed-auth \
		deny-protocol-version \
		force-retain \
		message-timestamp \
		payload-ban \
		payload-modification \
		payload-size-stats \
		plugin-event-stats \
		print-ip-on-publish \
		topic-modification \
		wildcard-temp

.PHONY : all binary check clean reallyclean test test-compile install uninstall

all :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d}; done

binary :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done

clean :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done

reallyclean :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done

test-compile:

check : test
test: test-compile 
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done

install :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done

uninstall :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done
