include ../../config.mk

ifneq ($(UNAME),SunOS)
	LIB_LDFLAGS:=$(LDFLAGS) -Wl,-soname,libmosquittopp.so.${SOVERSION}
endif

.PHONY : clean install

ALL_DEPS=libmosquittopp.so.${SOVERSION}

ifeq ($(WITH_STATIC_LIBRARIES),yes)
    ALL_DEPS+=libmosquittopp.a
endif

all : ${ALL_DEPS}

install : all
	$(INSTALL) -d "${DESTDIR}${libdir}/"
	$(INSTALL) ${STRIP_OPTS} libmosquittopp.so.${SOVERSION} "${DESTDIR}${libdir}/libmosquittopp.so.${SOVERSION}"
	ln -sf libmosquittopp.so.${SOVERSION} "${DESTDIR}${libdir}/libmosquittopp.so"
ifeq ($(WITH_STATIC_LIBRARIES),yes)
	$(INSTALL) libmosquittopp.a "${DESTDIR}${libdir}/libmosquittopp.a"
	${CROSS_COMPILE}${STRIP} -g --strip-unneeded "${DESTDIR}${libdir}/libmosquittopp.a"
endif
	$(INSTALL) -d "${DESTDIR}${incdir}/"
	$(INSTALL) mosquittopp.h "${DESTDIR}${incdir}/mosquittopp.h"
	$(INSTALL) -d "${DESTDIR}${libdir}/pkgconfig/"
	$(INSTALL) -m644 ../../libmosquittopp.pc.in "${DESTDIR}${libdir}/pkgconfig/libmosquittopp.pc"
	sed ${SEDINPLACE} -e "s#@CMAKE_INSTALL_PREFIX@#${prefix}#" -e "s#@CMAKE_INSTALL_LIBDIR@#lib${LIB_SUFFIX}#" -e "s#@VERSION@#${VERSION}#" "${DESTDIR}${libdir}/pkgconfig/libmosquittopp.pc"

uninstall :
	-rm -f "${DESTDIR}${libdir}/libmosquittopp.so.${SOVERSION}"
	-rm -f "${DESTDIR}${libdir}/libmosquittopp.so"
	-rm -f "${DESTDIR}${libdir}/libmosquittopp.a"
	-rm -f "${DESTDIR}${incdir}/mosquittopp.h"

clean :
	-rm -f *.o libmosquittopp.so.${SOVERSION} libmosquittopp.a

libmosquittopp.so.${SOVERSION} : mosquittopp.o
	${CROSS_COMPILE}$(CXX) -shared $(LIB_LDFLAGS) $< -o $@ ../libmosquitto.so.${SOVERSION} $(LIB_LIDADD)

libmosquittopp.a : mosquittopp.o
	${CROSS_COMPILE}$(AR) cr $@ $^

mosquittopp.o : mosquittopp.cpp mosquittopp.h
	${CROSS_COMPILE}$(CXX) $(LIB_CPPFLAGS) $(LIB_CXXFLAGS) -c $< -o $@

