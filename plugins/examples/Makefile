DIRS= \
		add-properties \
		auth-by-ip \
		client-lifetime-stats \
		client-properties \
		connection-state \
		delayed-auth \
		force-retain \
		limit-subscription-qos \
		message-timestamp \
		payload-modification \
		payload-size-stats \
		plugin-event-stats \
		print-ip-on-publish \
		topic-modification \
		topic-jail \
		wildcard-temp

.PHONY : all binary check clean reallyclean test install uninstall

all :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d}; done

binary :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done

clean :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done

reallyclean :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done

check : test
test :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done

install :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done

uninstall :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} $@; done
