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
	$(INSTALL) -d "${DESTDIR}$(prefix)/lib${LIB_SUFFIX}/"
	$(INSTALL) ${STRIP_OPTS} libmosquittopp.so.${SOVERSION} "${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libmosquittopp.so.${SOVERSION}"
	ln -sf libmosquittopp.so.${SOVERSION} "${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libmosquittopp.so"
ifeq ($(WITH_STATIC_LIBRARIES),yes)
	$(INSTALL) libmosquittopp.a "${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libmosquittopp.a"
	${CROSS_COMPILE}${STRIP} -g --strip-unneeded "${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libmosquittopp.a"
endif
	$(INSTALL) -d "${DESTDIR}${prefix}/include/"
	$(INSTALL) mosquittopp.h "${DESTDIR}${prefix}/include/mosquittopp.h"
	
uninstall :
	-rm -f "${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libmosquittopp.so.${SOVERSION}"
	-rm -f "${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libmosquittopp.so"
	-rm -f "${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libmosquittopp.a"
	-rm -f "${DESTDIR}${prefix}/include/mosquittopp.h"

clean :
	-rm -f *.o libmosquittopp.so.${SOVERSION} libmosquittopp.a

libmosquittopp.so.${SOVERSION} : mosquittopp.o
	${CROSS_COMPILE}$(CXX) -shared $(LIB_LDFLAGS) $< -o $@ ../libmosquitto.so.${SOVERSION}

libmosquittopp.a : mosquittopp.o
	${CROSS_COMPILE}$(AR) cr $@ $^

mosquittopp.o : mosquittopp.cpp mosquittopp.h
	${CROSS_COMPILE}$(CXX) $(LIB_CXXFLAGS) -c $< -o $@

