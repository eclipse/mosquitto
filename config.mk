# =============================================================================
# User configuration section.
#
# These options control compilation on all systems apart from Windows and Mac
# OS X. Use CMake to compile on Windows and Mac.
#
# Largely, these are options that are designed to make mosquitto run more
# easily in restrictive environments by removing features.
#
# Modify the variable below to enable/disable features.
#
# Can also be overriden at the command line, e.g.:
#
# make WITH_TLS=no
# =============================================================================

# Uncomment to compile the broker with tcpd/libwrap support.
#WITH_WRAP:=yes

# Comment out to disable SSL/TLS support in the broker and client.
# Disabling this will also mean that passwords must be stored in plain text. It
# is strongly recommended that you only disable WITH_TLS if you are not using
# password authentication at all.
WITH_TLS:=yes

# Comment out to disable TLS/PSK support in the broker and client. Requires
# WITH_TLS=yes.
# This must be disabled if using openssl < 1.0.
WITH_TLS_PSK:=yes

# Comment out to disable client threading support.
WITH_THREADING:=yes

# Comment out to remove bridge support from the broker. This allow the broker
# to connect to other brokers and subscribe/publish to topics. You probably
# want to leave this included unless you want to save a very small amount of
# memory size and CPU time.
WITH_BRIDGE:=yes

# Comment out to remove persistent database support from the broker. This
# allows the broker to store retained messages and durable subscriptions to a
# file periodically and on shutdown. This is usually desirable (and is
# suggested by the MQTT spec), but it can be disabled if required.
WITH_PERSISTENCE:=yes

# Comment out to remove memory tracking support from the broker. If disabled,
# mosquitto won't track heap memory usage nor export '$SYS/broker/heap/current
# size', but will use slightly less memory and CPU time.
WITH_MEMORY_TRACKING:=yes

# Compile with database upgrading support? If disabled, mosquitto won't
# automatically upgrade old database versions.
# Not currently supported.
#WITH_DB_UPGRADE:=yes

# Comment out to remove publishing of the $SYS topic hierarchy containing
# information about the broker state.
WITH_SYS_TREE:=yes

# Build with systemd support. If enabled, mosquitto will notify systemd after
# initialization. See README in service/systemd/ for more information.
WITH_SYSTEMD:=no

# Build with SRV lookup support.
WITH_SRV:=no

# Build with websockets support on the broker.
WITH_WEBSOCKETS:=no

# Use elliptic keys in broker
WITH_EC:=yes

# Build man page documentation by default.
WITH_DOCS:=yes

# Build with client support for SOCK5 proxy.
WITH_SOCKS:=yes

# Strip executables and shared libraries on install.
WITH_STRIP:=no

# Build static libraries
WITH_STATIC_LIBRARIES:=no

# Use this variable to add extra library dependencies when building the clients
# with the static libmosquitto library. This may be required on some systems
# where e.g. -lz or -latomic are needed for openssl.
CLIENT_STATIC_LDADD:=

# Build shared libraries
WITH_SHARED_LIBRARIES:=yes

# Build with async dns lookup support for bridges (temporary). Requires glibc.
#WITH_ADNS:=yes

# Build with epoll support.
WITH_EPOLL:=yes

# Build with bundled uthash.h
WITH_BUNDLED_DEPS:=yes

# Build with coverage options
WITH_COVERAGE:=no

# Build with unix domain socket support
WITH_UNIX_SOCKETS:=yes

# Build mosquitto_sub with cJSON support
WITH_CJSON:=yes

# Build mosquitto with support for the $CONTROL topics.
WITH_CONTROL:=yes

# Build the broker with the jemalloc allocator
WITH_JEMALLOC:=no

# Build with xtreport capability. This is for debugging purposes and is
# probably of no particular interest to end users.
WITH_XTREPORT=no

# =============================================================================
# End of user configuration
# =============================================================================


# Also bump lib/mosquitto.h, CMakeLists.txt,
# installer/mosquitto.nsi, installer/mosquitto64.nsi
VERSION=2.0.1

# Client library SO version. Bump if incompatible API/ABI changes are made.
SOVERSION=1

# Man page generation requires xsltproc and docbook-xsl
XSLTPROC=xsltproc --nonet
# For html generation
DB_HTML_XSL=man/html.xsl

#MANCOUNTRIES=en_GB

UNAME:=$(shell uname -s)

ifeq ($(UNAME),SunOS)
	ifeq ($(CC),cc)
		CFLAGS?=-O
	else
		CFLAGS?=-Wall -ggdb -O2
	endif
else
	CFLAGS?=-Wall -ggdb -O2 -Wconversion
endif

STATIC_LIB_DEPS:=

APP_CPPFLAGS=$(CPPFLAGS) -I. -I../../ -I../../include -I../../src -I../../lib
APP_CFLAGS=$(CFLAGS) -DVERSION=\""${VERSION}\""
APP_LDFLAGS:=$(LDFLAGS)

LIB_CPPFLAGS=$(CPPFLAGS) -I. -I.. -I../include -I../../include
LIB_CFLAGS:=$(CFLAGS)
LIB_CXXFLAGS:=$(CXXFLAGS)
LIB_LDFLAGS:=$(LDFLAGS)
LIB_LIBADD:=$(LIBADD)

BROKER_CPPFLAGS:=$(LIB_CPPFLAGS) -I../lib
BROKER_CFLAGS:=${CFLAGS} -DVERSION="\"${VERSION}\"" -DWITH_BROKER
BROKER_LDFLAGS:=${LDFLAGS}
BROKER_LDADD:=

CLIENT_CPPFLAGS:=$(CPPFLAGS) -I.. -I../include
CLIENT_CFLAGS:=${CFLAGS} -DVERSION="\"${VERSION}\""
CLIENT_LDFLAGS:=$(LDFLAGS) -L../lib
CLIENT_LDADD:=

PASSWD_LDADD:=

PLUGIN_CPPFLAGS:=$(CPPFLAGS) -I../.. -I../../include
PLUGIN_CFLAGS:=$(CFLAGS) -fPIC
PLUGIN_LDFLAGS:=$(LDFLAGS)

ifneq ($(or $(findstring $(UNAME),FreeBSD), $(findstring $(UNAME),OpenBSD), $(findstring $(UNAME),NetBSD)),)
	BROKER_LDADD:=$(BROKER_LDADD) -lm
	SEDINPLACE:=-i ""
else
	BROKER_LDADD:=$(BROKER_LDADD) -ldl -lm
	SEDINPLACE:=-i
endif

ifeq ($(UNAME),Linux)
	BROKER_LDADD:=$(BROKER_LDADD) -lrt
	BROKER_LDFLAGS:=$(BROKER_LDFLAGS) -Wl,--dynamic-list=linker.syms
	LIB_LIBADD:=$(LIB_LIBADD) -lrt
endif

ifeq ($(WITH_SHARED_LIBRARIES),yes)
	CLIENT_LDADD:=${CLIENT_LDADD} ../lib/libmosquitto.so.${SOVERSION}
endif

ifeq ($(UNAME),SunOS)
	ifeq ($(CC),cc)
		LIB_CFLAGS:=$(LIB_CFLAGS) -xc99 -KPIC
	else
		LIB_CFLAGS:=$(LIB_CFLAGS) -fPIC
	endif

	ifeq ($(CXX),CC)
		LIB_CXXFLAGS:=$(LIB_CXXFLAGS) -KPIC
	else
		LIB_CXXFLAGS:=$(LIB_CXXFLAGS) -fPIC
	endif
else
	LIB_CFLAGS:=$(LIB_CFLAGS) -fPIC
	LIB_CXXFLAGS:=$(LIB_CXXFLAGS) -fPIC
endif

ifneq ($(UNAME),SunOS)
	LIB_LDFLAGS:=$(LIB_LDFLAGS) -Wl,--version-script=linker.version -Wl,-soname,libmosquitto.so.$(SOVERSION)
endif

ifeq ($(UNAME),QNX)
	BROKER_LDADD:=$(BROKER_LDADD) -lsocket
	LIB_LIBADD:=$(LIB_LIBADD) -lsocket
endif

ifeq ($(WITH_WRAP),yes)
	BROKER_LDADD:=$(BROKER_LDADD) -lwrap
	BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) -DWITH_WRAP
endif

ifeq ($(WITH_TLS),yes)
	APP_CPPFLAGS:=$(APP_CPPFLAGS) -DWITH_TLS
	BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) -DWITH_TLS
	BROKER_LDADD:=$(BROKER_LDADD) -lssl -lcrypto
	CLIENT_CPPFLAGS:=$(CLIENT_CPPFLAGS) -DWITH_TLS
	LIB_CPPFLAGS:=$(LIB_CPPFLAGS) -DWITH_TLS
	LIB_LIBADD:=$(LIB_LIBADD) -lssl -lcrypto
	PASSWD_LDADD:=$(PASSWD_LDADD) -lcrypto
	STATIC_LIB_DEPS:=$(STATIC_LIB_DEPS) -lssl -lcrypto

	ifeq ($(WITH_TLS_PSK),yes)
		BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) -DWITH_TLS_PSK
		LIB_CPPFLAGS:=$(LIB_CPPFLAGS) -DWITH_TLS_PSK
		CLIENT_CPPFLAGS:=$(CLIENT_CPPFLAGS) -DWITH_TLS_PSK
	endif
endif

ifeq ($(WITH_THREADING),yes)
	LIB_LIBADD:=$(LIB_LIBADD) -lpthread
	LIB_CPPFLAGS:=$(LIB_CPPFLAGS) -DWITH_THREADING
	CLIENT_CPPFLAGS:=$(CLIENT_CPPFLAGS) -DWITH_THREADING
	STATIC_LIB_DEPS:=$(STATIC_LIB_DEPS) -lpthread
endif

ifeq ($(WITH_SOCKS),yes)
	LIB_CPPFLAGS:=$(LIB_CPPFLAGS) -DWITH_SOCKS
	CLIENT_CPPFLAGS:=$(CLIENT_CPPFLAGS) -DWITH_SOCKS
endif

ifeq ($(WITH_BRIDGE),yes)
	BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) -DWITH_BRIDGE
endif

ifeq ($(WITH_PERSISTENCE),yes)
	BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) -DWITH_PERSISTENCE
endif

ifeq ($(WITH_MEMORY_TRACKING),yes)
	ifneq ($(UNAME),SunOS)
		BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) -DWITH_MEMORY_TRACKING
	endif
endif

ifeq ($(WITH_SYS_TREE),yes)
	BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) -DWITH_SYS_TREE
endif

ifeq ($(WITH_SYSTEMD),yes)
	BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) -DWITH_SYSTEMD
	BROKER_LDADD:=$(BROKER_LDADD) -lsystemd
endif

ifeq ($(WITH_SRV),yes)
	LIB_CPPFLAGS:=$(LIB_CPPFLAGS) -DWITH_SRV
	LIB_LIBADD:=$(LIB_LIBADD) -lcares
	CLIENT_CPPFLAGS:=$(CLIENT_CPPFLAGS) -DWITH_SRV
	STATIC_LIB_DEPS:=$(STATIC_LIB_DEPS) -lcares
endif

ifeq ($(UNAME),SunOS)
	BROKER_LDADD:=$(BROKER_LDADD) -lsocket -lnsl
	LIB_LIBADD:=$(LIB_LIBADD) -lsocket -lnsl
endif

ifeq ($(WITH_EC),yes)
	BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) -DWITH_EC
endif

ifeq ($(WITH_ADNS),yes)
	BROKER_LDADD:=$(BROKER_LDADD) -lanl
	BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) -DWITH_ADNS
endif

ifeq ($(WITH_CONTROL),yes)
	BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) -DWITH_CONTROL
endif

MAKE_ALL:=mosquitto
ifeq ($(WITH_DOCS),yes)
	MAKE_ALL:=$(MAKE_ALL) docs
endif

ifeq ($(WITH_JEMALLOC),yes)
	BROKER_LDADD:=$(BROKER_LDADD) -ljemalloc
endif

ifeq ($(WITH_UNIX_SOCKETS),yes)
	BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) -DWITH_UNIX_SOCKETS
	LIB_CPPFLAGS:=$(LIB_CPPFLAGS) -DWITH_UNIX_SOCKETS
	CLIENT_CPPFLAGS:=$(CLIENT_CPPFLAGS) -DWITH_UNIX_SOCKETS
endif

ifeq ($(WITH_WEBSOCKETS),yes)
	BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) -DWITH_WEBSOCKETS
	BROKER_LDADD:=$(BROKER_LDADD) -lwebsockets
endif

ifeq ($(WITH_WEBSOCKETS),static)
	BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) -DWITH_WEBSOCKETS
	BROKER_LDADD:=$(BROKER_LDADD) -static -lwebsockets
endif

INSTALL?=install
prefix?=/usr/local
incdir?=${prefix}/include
libdir?=${prefix}/lib${LIB_SUFFIX}
localedir?=${prefix}/share/locale
mandir?=${prefix}/share/man
STRIP?=strip

ifeq ($(WITH_STRIP),yes)
	STRIP_OPTS?=-s --strip-program=${CROSS_COMPILE}${STRIP}
endif

ifeq ($(WITH_EPOLL),yes)
	ifeq ($(UNAME),Linux)
		BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) -DWITH_EPOLL
	endif
endif

ifeq ($(WITH_BUNDLED_DEPS),yes)
	BROKER_CPPFLAGS:=$(BROKER_CPPFLAGS) -I../deps
	LIB_CPPFLAGS:=$(LIB_CPPFLAGS) -I../deps
	PLUGIN_CPPFLAGS:=$(PLUGIN_CPPFLAGS) -I../../deps
endif

ifeq ($(WITH_COVERAGE),yes)
	BROKER_CFLAGS:=$(BROKER_CFLAGS) -coverage
	BROKER_LDFLAGS:=$(BROKER_LDFLAGS) -coverage
	PLUGIN_CFLAGS:=$(PLUGIN_CFLAGS) -coverage
	PLUGIN_LDFLAGS:=$(PLUGIN_LDFLAGS) -coverage
	LIB_CFLAGS:=$(LIB_CFLAGS) -coverage
	LIB_LDFLAGS:=$(LIB_LDFLAGS) -coverage
	CLIENT_CFLAGS:=$(CLIENT_CFLAGS) -coverage
	CLIENT_LDFLAGS:=$(CLIENT_LDFLAGS) -coverage
endif

ifeq ($(WITH_CJSON),yes)
	CLIENT_CFLAGS:=$(CLIENT_CFLAGS) -DWITH_CJSON
	CLIENT_LDADD:=$(CLIENT_LDADD) -lcjson
	CLIENT_STATIC_LDADD:=$(CLIENT_STATIC_LDADD) -lcjson
	CLIENT_LDFLAGS:=$(CLIENT_LDFLAGS)
endif

ifeq ($(WITH_XTREPORT),yes)
	BROKER_CFLAGS:=$(BROKER_CFLAGS) -DWITH_XTREPORT
endif

BROKER_LDADD:=${BROKER_LDADD} ${LDADD}
CLIENT_LDADD:=${CLIENT_LDADD} ${LDADD}
PASSWD_LDADD:=${PASSWD_LDADD} ${LDADD}
