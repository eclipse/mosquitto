include config.mk

DIRS=lib client src
DOCDIRS=man
DISTDIRS=man

.PHONY : all mosquitto docs binary clean reallyclean test install uninstall dist sign copy

all : $(MAKE_ALL)

docs :
	set -e; for d in ${DOCDIRS}; do $(MAKE) -C $${d}; done

binary : mosquitto

mosquitto :
ifeq ($(UNAME),Darwin)
	$(error Please compile using CMake on Mac OS X)
endif

	set -e; for d in ${DIRS}; do $(MAKE) -C $${d}; done

clean :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} clean; done
	set -e; for d in ${DOCDIRS}; do $(MAKE) -C $${d} clean; done
	$(MAKE) -C test clean

reallyclean : 
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} reallyclean; done
	set -e; for d in ${DOCDIRS}; do $(MAKE) -C $${d} reallyclean; done
	$(MAKE) -C test reallyclean
	-rm -f *.orig

test : mosquitto
	$(MAKE) -C test test

install : mosquitto
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} install; done
ifeq ($(WITH_DOCS),yes)
	set -e; for d in ${DOCDIRS}; do $(MAKE) -C $${d} install; done
endif
	$(INSTALL) -d ${DESTDIR}/etc/mosquitto
	$(INSTALL) -m 644 mosquitto.conf ${DESTDIR}/etc/mosquitto/mosquitto.conf.example
	$(INSTALL) -m 644 aclfile.example ${DESTDIR}/etc/mosquitto/aclfile.example
	$(INSTALL) -m 644 pwfile.example ${DESTDIR}/etc/mosquitto/pwfile.example
	$(INSTALL) -m 644 pskfile.example ${DESTDIR}/etc/mosquitto/pskfile.example

uninstall :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} uninstall; done
	rm -f ${DESTDIR}/etc/mosquitto/mosquitto.conf
	rm -f ${DESTDIR}/etc/mosquitto/aclfile.example
	rm -f ${DESTDIR}/etc/mosquitto/pwfile.example
	rm -f ${DESTDIR}/etc/mosquitto/pskfile.example

dist : reallyclean
	set -e; for d in ${DISTDIRS}; do $(MAKE) -C $${d} dist; done
	
	mkdir -p dist/mosquitto-${VERSION}
	cp -r client examples installer lib logo man misc security service src test about.html aclfile.example ChangeLog.txt CMakeLists.txt compiling.txt config.h config.mk CONTRIBUTING.md edl-v10 epl-v10 LICENSE.txt Makefile mosquitto.conf notice.html pskfile.example pwfile.example readme.md readme-windows.txt dist/mosquitto-${VERSION}/
	cd dist; tar -zcf mosquitto-${VERSION}.tar.gz mosquitto-${VERSION}/
	set -e; for m in man/*.xml; \
		do \
		hfile=$$(echo $${m} | sed -e 's#man/\(.*\)\.xml#\1#' | sed -e 's/\./-/g'); \
		$(XSLTPROC) $(DB_HTML_XSL) $${m} > dist/$${hfile}.html; \
	done


sign : dist
	cd dist; gpg --detach-sign -a mosquitto-${VERSION}.tar.gz

copy : sign
	cd dist; scp mosquitto-${VERSION}.tar.gz mosquitto-${VERSION}.tar.gz.asc mosquitto:site/mosquitto.org/files/source/
	cd dist; scp *.html mosquitto:site/mosquitto.org/man/
	scp ChangeLog.txt mosquitto:site/mosquitto.org/

