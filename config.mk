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

# Comment out to disable client client threading support.
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

# Build with SRV lookup support.
WITH_SRV:=yes

# Build using libuuid for clientid generation (Linux only - please report if
# supported on your platform).
WITH_UUID:=yes

# Build with websockets support on the broker.
WITH_WEBSOCKETS:=no

# Use elliptic keys in broker
WITH_EC:=yes

# Build man page documentation by default.
WITH_DOCS:=yes

# Build with client support for SOCK5 proxy.
WITH_SOCKS:=yes

# Build with async dns lookup support for bridges (temporary). Requires glibc.
#WITH_ADNS:=yes

# =============================================================================
# End of user configuration
# =============================================================================


# Also bump lib/mosquitto.h, CMakeLists.txt,
# installer/mosquitto.nsi, installer/mosquitto-cygwin.nsi
VERSION=1.4.14
TIMESTAMP:=$(shell date "+%F %T%z")

# Client library SO version. Bump if incompatible API/ABI changes are made.
SOVERSION=1

# Man page generation requires xsltproc and docbook-xsl
XSLTPROC=xsltproc
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
	CFLAGS?=-Wall -ggdb -O2
endif

LIB_CFLAGS:=${CFLAGS} ${CPPFLAGS} -I. -I.. -I../lib
LIB_CXXFLAGS:=$(LIB_CFLAGS) ${CPPFLAGS}
LIB_LDFLAGS:=${LDFLAGS}

BROKER_CFLAGS:=${LIB_CFLAGS} ${CPPFLAGS} -DVERSION="\"${VERSION}\"" -DTIMESTAMP="\"${TIMESTAMP}\"" -DWITH_BROKER
CLIENT_CFLAGS:=${CFLAGS} ${CPPFLAGS} -I../lib -DVERSION="\"${VERSION}\""

ifneq ($(or $(findstring $(UNAME),FreeBSD), $(findstring $(UNAME),OpenBSD)),)
	BROKER_LIBS:=-lm
else
	BROKER_LIBS:=-ldl -lm
endif
LIB_LIBS:=
PASSWD_LIBS:=

ifeq ($(UNAME),Linux)
	BROKER_LIBS:=$(BROKER_LIBS) -lrt -Wl,--dynamic-list=linker.syms
	LIB_LIBS:=$(LIB_LIBS) -lrt
endif

CLIENT_LDFLAGS:=$(LDFLAGS) -L../lib ../lib/libmosquitto.so.${SOVERSION}

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
	BROKER_LIBS:=$(BROKER_LIBS) -lsocket
	LIB_LIBS:=$(LIB_LIBS) -lsocket
endif

ifeq ($(WITH_WRAP),yes)
	BROKER_LIBS:=$(BROKER_LIBS) -lwrap
	BROKER_CFLAGS:=$(BROKER_CFLAGS) -DWITH_WRAP
endif

ifeq ($(WITH_TLS),yes)
	BROKER_LIBS:=$(BROKER_LIBS) -lssl -lcrypto
	LIB_LIBS:=$(LIB_LIBS) -lssl -lcrypto
	BROKER_CFLAGS:=$(BROKER_CFLAGS) -DWITH_TLS
	LIB_CFLAGS:=$(LIB_CFLAGS) -DWITH_TLS
	PASSWD_LIBS:=-lcrypto
	CLIENT_CFLAGS:=$(CLIENT_CFLAGS) -DWITH_TLS

	ifeq ($(WITH_TLS_PSK),yes)
		BROKER_CFLAGS:=$(BROKER_CFLAGS) -DWITH_TLS_PSK
		LIB_CFLAGS:=$(LIB_CFLAGS) -DWITH_TLS_PSK
		CLIENT_CFLAGS:=$(CLIENT_CFLAGS) -DWITH_TLS_PSK
	endif
endif

ifeq ($(WITH_THREADING),yes)
	LIB_LIBS:=$(LIB_LIBS) -lpthread
	LIB_CFLAGS:=$(LIB_CFLAGS) -DWITH_THREADING
endif

ifeq ($(WITH_SOCKS),yes)
	LIB_CFLAGS:=$(LIB_CFLAGS) -DWITH_SOCKS
	CLIENT_CFLAGS:=$(CLIENT_CFLAGS) -DWITH_SOCKS
endif

ifeq ($(WITH_UUID),yes)
	ifeq ($(UNAME),Linux)
		BROKER_CFLAGS:=$(BROKER_CFLAGS) -DWITH_UUID
		BROKER_LIBS:=$(BROKER_LIBS) -luuid
	endif
endif

ifeq ($(WITH_BRIDGE),yes)
	BROKER_CFLAGS:=$(BROKER_CFLAGS) -DWITH_BRIDGE
endif

ifeq ($(WITH_PERSISTENCE),yes)
	BROKER_CFLAGS:=$(BROKER_CFLAGS) -DWITH_PERSISTENCE
endif

ifeq ($(WITH_MEMORY_TRACKING),yes)
	ifneq ($(UNAME),SunOS)
		BROKER_CFLAGS:=$(BROKER_CFLAGS) -DWITH_MEMORY_TRACKING
	endif
endif

#ifeq ($(WITH_DB_UPGRADE),yes)
#	BROKER_CFLAGS:=$(BROKER_CFLAGS) -DWITH_DB_UPGRADE
#endif

ifeq ($(WITH_SYS_TREE),yes)
	BROKER_CFLAGS:=$(BROKER_CFLAGS) -DWITH_SYS_TREE
endif

ifeq ($(WITH_SRV),yes)
	LIB_CFLAGS:=$(LIB_CFLAGS) -DWITH_SRV
	LIB_LIBS:=$(LIB_LIBS) -lcares
	CLIENT_CFLAGS:=$(CLIENT_CFLAGS) -DWITH_SRV
endif

ifeq ($(WITH_WEBSOCKETS),yes)
	BROKER_CFLAGS:=$(BROKER_CFLAGS) -DWITH_WEBSOCKETS
	BROKER_LIBS:=$(BROKER_LIBS) -lwebsockets
endif

ifeq ($(UNAME),SunOS)
	BROKER_LIBS:=$(BROKER_LIBS) -lsocket -lnsl
	LIB_LIBS:=$(LIB_LIBS) -lsocket -lnsl
endif

ifeq ($(WITH_EC),yes)
	BROKER_CFLAGS:=$(BROKER_CFLAGS) -DWITH_EC
endif

ifeq ($(WITH_ADNS),yes)
	BROKER_LIBS:=$(BROKER_LIBS) -lanl
	BROKER_CFLAGS:=$(BROKER_CFLAGS) -DWITH_ADNS
endif

MAKE_ALL:=mosquitto
ifeq ($(WITH_DOCS),yes)
	MAKE_ALL:=$(MAKE_ALL) docs
endif

INSTALL?=install
prefix=/usr/local
mandir=${prefix}/share/man
localedir=${prefix}/share/locale
STRIP?=strip
