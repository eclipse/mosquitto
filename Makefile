include config.mk

DIRS=libcommon lib apps client plugins src
DOCDIRS=man
DISTDIRS=man
DISTFILES= \
	apps/ \
	client/ \
	cmake/ \
	common/ \
	dashboard/ \
	deps/ \
	doc/ \
	docker/ \
	examples/ \
	fuzzing/ \
	include/ \
	installer/ \
	libcommon/ \
	lib/ \
	logo/ \
	make/ \
	man/ \
	misc/ \
	plugins/ \
	security/ \
	service/ \
	snap/ \
	src/ \
	test/ \
	www/ \
	.github \
	\
	.editorconfig \
	.gitignore \
	.uncrustify.cfg \
	buildtest.py \
	codecov.yml \
	CMakeLists.txt \
	CITATION.cff \
	CONTRIBUTING.md \
	ChangeLog.txt \
	format.sh \
	LICENSE.txt \
	Makefile \
	about.html \
	aclfile.example \
	config.h \
	config.mk \
	edl-v10 \
	epl-v20 \
	libmosquitto.pc.in \
	libmosquittopp.pc.in \
	mosquitto.conf \
	NOTICE.md \
	pskfile.example \
	pwfile.example \
	README-compiling.md \
	README-letsencrypt.md \
	README-tests.md \
	README-windows.txt \
	README.md \
	run_tests.py \
	set-version.sh \
	SECURITY.md \
	THANKS.txt \
	vcpkg.json

.PHONY : all mosquitto api docs binary check clean reallyclean test test-compile install uninstall dist sign copy localdocker

all : $(MAKE_ALL)

api :
	mkdir -p api p
	naturaldocs -o HTML api -i include -p p
	rm -rf p

docs :
	set -e; for d in ${DOCDIRS}; do $(MAKE) -C $${d}; done

binary : mosquitto

binary-all : mosquitto test-compile

mosquitto :
ifeq ($(UNAME),Darwin)
	$(error Please compile using CMake on Mac OS X)
endif
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d}; done

fuzzing : mosquitto
	$(MAKE) -C fuzzing

clean :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} clean; done
	set -e; for d in ${DOCDIRS}; do $(MAKE) -C $${d} clean; done
	$(MAKE) -C test clean
	$(MAKE) -C fuzzing clean

reallyclean :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} reallyclean; done
	set -e; for d in ${DOCDIRS}; do $(MAKE) -C $${d} reallyclean; done
	$(MAKE) -C test reallyclean
	-rm -f *.orig

check : test

test-compile: mosquitto lib
	$(MAKE) -C test test-compile
	$(MAKE) -C plugins test-compile

test : mosquitto lib apps test-compile
	$(MAKE) -C test test
	$(MAKE) -C plugins test

ptest : mosquitto
	$(MAKE) -C test ptest

utest : mosquitto
	$(MAKE) -C test utest

install : all
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} install; done
ifeq ($(WITH_DOCS),yes)
	set -e; for d in ${DOCDIRS}; do $(MAKE) -C $${d} install; done
endif
	$(INSTALL) -d "${DESTDIR}/etc/mosquitto"
	$(INSTALL) -m 644 mosquitto.conf "${DESTDIR}/etc/mosquitto/mosquitto.conf.example"
	$(INSTALL) -m 644 aclfile.example "${DESTDIR}/etc/mosquitto/aclfile.example"
	$(INSTALL) -m 644 pwfile.example "${DESTDIR}/etc/mosquitto/pwfile.example"
	$(INSTALL) -m 644 pskfile.example "${DESTDIR}/etc/mosquitto/pskfile.example"
	$(INSTALL) -d "${DESTDIR}$(prefix)/include/mosquitto"
	$(INSTALL) include/mosquitto/*.h "${DESTDIR}${prefix}/include/mosquitto/"
	$(INSTALL) include/mosquitto.h "${DESTDIR}${prefix}/include/mosquitto.h"
	$(INSTALL) include/mosquitto_broker.h "${DESTDIR}${prefix}/include/mosquitto_broker.h"
	$(INSTALL) include/mosquitto_plugin.h "${DESTDIR}${prefix}/include/mosquitto_plugin.h"
	$(INSTALL) include/mosquittopp.h "${DESTDIR}${prefix}/include/mosquittopp.h"
	$(INSTALL) include/mqtt_protocol.h "${DESTDIR}${prefix}/include/mqtt_protocol.h"

uninstall :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} uninstall; done
	rm -f "${DESTDIR}/etc/mosquitto/mosquitto.conf.example"
	rm -f "${DESTDIR}/etc/mosquitto/aclfile.example"
	rm -f "${DESTDIR}/etc/mosquitto/pwfile.example"
	rm -f "${DESTDIR}/etc/mosquitto/pskfile.example"
	rm -f "${DESTDIR}${prefix}/include/mosquitto.h"
	rm -f "${DESTDIR}${prefix}/include/mosquitto/broker.h"
	rm -f "${DESTDIR}${prefix}/include/mosquitto/broker_control.h"
	rm -f "${DESTDIR}${prefix}/include/mosquitto/broker_plugin.h"
	rm -f "${DESTDIR}${prefix}/include/mosquitto/libmosquittopp.h"
	rm -f "${DESTDIR}${prefix}/include/mosquitto/mqtt_protocol.h"
	rm -f "${DESTDIR}${prefix}/include/mosquitto_broker.h"
	rm -f "${DESTDIR}${prefix}/include/mosquitto_plugin.h"
	rm -f "${DESTDIR}${prefix}/include/mosquittopp.h"
	rm -f "${DESTDIR}${prefix}/include/mqtt_protocol.h"

dist : reallyclean
	set -e; for d in ${DISTDIRS}; do $(MAKE) -C $${d} dist; done
	mkdir -p dist/mosquitto-${VERSION}
	cp -r ${DISTFILES} dist/mosquitto-${VERSION}/
	cd dist; tar -zcf mosquitto-${VERSION}.tar.gz mosquitto-${VERSION}/

sign : dist
	cd dist; gpg --detach-sign -a mosquitto-${VERSION}.tar.gz

copy : sign
	cd dist; scp mosquitto-${VERSION}.tar.gz mosquitto-${VERSION}.tar.gz.asc mosquitto:site/mosquitto.org/files/source/
	scp ChangeLog.txt mosquitto:site/mosquitto.org/

coverage :
	lcov --capture -d apps -d client -d lib -d plugins -d src --output-file coverage.info --no-external --ignore-errors empty
	genhtml --ignore-errors inconsistent coverage.info --output-directory out

localdocker : reallyclean
	set -e; for d in ${DISTDIRS}; do $(MAKE) -C $${d} dist; done
	rm -rf dockertmp/
	mkdir -p dockertmp/mosquitto-${VERSION}
	cp -r ${DISTFILES} dockertmp/mosquitto-${VERSION}/
	cd dockertmp/; tar -zcf mosq.tar.gz mosquitto-${VERSION}/
	cp dockertmp/mosq.tar.gz docker/local
	rm -rf dockertmp/
	cd docker/local && docker build . -t eclipse-mosquitto:local --build-arg VERSION=${VERSION}
