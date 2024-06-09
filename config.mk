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

# Uncomment to activate a consistency check on the usage of the memory tracking
# alloc/free function use. Any memory allocated without a tracking function,
# but freed with the tracking function will trigger an invalid memory read in
# memory trackers like valgrind memcheck or ASAN.
#ALLOC_MISMATCH_INVALID_READ:=yes

# Uncomment to activate consistency check on the usage of the memory tracking
# alloc/free function use. Any memory allocated without a tracking function,
# but freed with the tracking function will trigger an abort.
#ALLOC_MISMATCH_ABORT:=yes

# Compile with database upgrading support? If disabled, mosquitto won't
# automatically upgrade old database versions.
# Not currently supported.
#WITH_DB_UPGRADE:=yes

# Comment out to remove publishing of the $SYS topic hierarchy containing
# information about the broker state.
WITH_SYS_TREE:=yes

# Build with systemd support. If enabled, mosquitto will notify systemd after
# initialization. See README in service/systemd/ for more information.
# Setting to yes means the libsystemd-dev or similar package will need to be
# installed.
WITH_SYSTEMD:=no

# Build with SRV lookup support.
WITH_SRV:=no

# Build with websockets support on the broker.
# Set to yes to build with new websockets support
# Set to lws to build with old libwebsockets code
# Set to no to disable
WITH_WEBSOCKETS:=yes

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

# Build mosquitto with support for the $CONTROL topics.
WITH_CONTROL:=yes

# Build the broker with the jemalloc allocator
WITH_JEMALLOC:=no

# Build with xtreport capability. This is for debugging purposes and is
# probably of no particular interest to end users.
WITH_XTREPORT=no

# Use the old O(n) keepalive check routine, instead of the new O(1) keepalive
# check routine. See src/keepalive.c for notes on this.
WITH_OLD_KEEPALIVE=no

# Use link time optimisation - note that enabling this currently prevents
# broker plugins from working.
#WITH_LTO=yes

# Build with sqlite3 support - this enables the sqlite persistence plugin.
WITH_SQLITE=yes

# Build broker for fuzzing only - does not work as a normal broker. This is
# currently only suitable for use with oss-fuzz.
WITH_FUZZING=no

# Build with argon2id support for password hashing.
WITH_ARGON2=yes

# Build using clang and with address sanitiser enabled
WITH_ASAN=no

# =============================================================================
# End of user configuration
# =============================================================================


# Also bump lib/mosquitto.h, CMakeLists.txt,
# installer/mosquitto.nsi, installer/mosquitto64.nsi
VERSION=2.1.0

# Client library SO version. Bump if incompatible API/ABI changes are made.
SOVERSION=1

# Man page generation requires xsltproc and docbook-xsl
XSLTPROC=xsltproc --nonet
# For html generation
DB_HTML_XSL=man/html.xsl

#MANCOUNTRIES=en_GB

MAKE_ALL:=mosquitto

UNAME:=$(shell uname -s)
ARCH:=$(shell uname -p)

INSTALL?=install
prefix?=/usr/local
incdir?=${prefix}/include
libdir?=${prefix}/lib${LIB_SUFFIX}
localedir?=${prefix}/share/locale
mandir?=${prefix}/share/man
STRIP?=strip

ifeq ($(UNAME),SunOS)
	ifeq ($(CC),cc)
		CFLAGS?=-O
	else
		CFLAGS?=-Wall -ggdb -O2
	endif
else
	CFLAGS?=-Wall -ggdb -O3 -Wconversion -Wextra -std=gnu99
	CXXFLAGS?=-Wall -ggdb -O3 -Wconversion -Wextra
endif

LOCAL_CPPFLAGS=$(CPPFLAGS)
LOCAL_CFLAGS=$(CFLAGS)
LOCAL_CXXFLAGS=$(CXXFLAGS)
LOCAL_LDFLAGS=$(LDFLAGS)
LOCAL_LIBADD=$(LIBADD)

LOCAL_CPPFLAGS+=-DVERSION=\""${VERSION}\"" -I${R} -I. -I${R}/include -I${R}/common

ifneq ($(or $(findstring $(UNAME),FreeBSD), $(findstring $(UNAME),OpenBSD), $(findstring $(UNAME),NetBSD)),)
	SEDINPLACE:=-i ""
else
ifeq ($(UNAME),SunOS)
	SEDINPLACE:=
else
	SEDINPLACE:=-i
endif
endif

ifeq ($(UNAME),QNX)
	LOCAL_LDADD+=-lsocket
endif

ifeq ($(UNAME),SunOS)
	LOCAL_LDADD+=-lsocket -lnsl
	LOCAL_LIBADD+=-lsocket -lnsl
endif

ifeq ($(WITH_FUZZING),yes)
	WITH_SHARED_LIBRARIES:=no
	WITH_STATIC_LIBRARIES:=yes
endif

ifeq ($(WITH_SHARED_LIBRARIES),yes)
	LIBMOSQ:=${R}/lib/libmosquitto.so.${SOVERSION}
else
	LIBMOSQ:=${R}/lib/libmosquitto.a
endif
LIBMOSQ_COMMON:=-Wl,--whole-archive ${R}/libcommon/libmosquitto_common.a -Wl,--no-whole-archive

ifeq ($(WITH_TLS),yes)
	LOCAL_CPPFLAGS+=-DWITH_TLS
	ifeq ($(WITH_TLS_PSK),yes)
		LOCAL_CPPFLAGS+=-DWITH_TLS_PSK
	endif
endif

ifeq ($(WITH_ASAN),yes)
	CC:=clang
	CXX:=clang++
	LOCAL_CFLAGS+=-fsanitize=address -fno-omit-frame-pointer
	LOCAL_CXXFLAGS+=-fsanitize=address -fno-omit-frame-pointer
	LOCAL_LDFLAGS+=-fsanitize=address -fno-omit-frame-pointer -static-libsan
endif

ifeq ($(WITH_LTO),yes)
	LOCAL_CFLAGS+=-flto
	LOCAL_LDFLAGS+=-flto
endif

ifeq ($(WITH_DOCS),yes)
	MAKE_ALL+=docs
endif

ifeq ($(WITH_JEMALLOC),yes)
	LOCAL_LDADD+=-ljemalloc
endif

ifeq ($(WITH_UNIX_SOCKETS),yes)
	LOCAL_CPPFLAGS+=-DWITH_UNIX_SOCKETS
endif

ifeq ($(WITH_WEBSOCKETS),yes)
	LOCAL_CPPFLAGS+=-DWITH_WEBSOCKETS=WS_IS_BUILTIN -I${R}/deps/picohttpparser
endif

ifeq ($(WITH_WEBSOCKETS),lws)
	LOCAL_CPPFLAGS+=-DWITH_WEBSOCKETS=WS_IS_LWS
	LOCAL_LDADD+=-lwebsockets
endif

ifeq ($(WITH_STRIP),yes)
	STRIP_OPTS?=-s --strip-program=${CROSS_COMPILE}${STRIP}
endif

ifeq ($(WITH_BUNDLED_DEPS),yes)
	LOCAL_CPPFLAGS+=-I${R}/deps
endif

ifeq ($(WITH_COVERAGE),yes)
	LOCAL_CFLAGS+=-coverage
	LOCAL_LDFLAGS+=-coverage
endif

ifeq ($(WITH_FUZZING),yes)
	MAKE_ALL+=fuzzing
	LOCAL_CPPFLAGS+=-DWITH_FUZZING
	LOCAL_CFLAGS+=-fPIC
	LOCAL_LDFLAGS+=-shared $(LOCAL_CFLAGS)
endif

ifeq ($(WITH_ARGON2),yes)
	LOCAL_CPPFLAGS+=-DWITH_ARGON2
	LIB_ARGON2=-largon2
	LIBMOSQ_COMMON+=${LIB_ARGON2}
endif
