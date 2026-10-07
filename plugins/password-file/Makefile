R=../..
include ${R}/config.mk

PLUGIN_NAME=mosquitto_password_file
LOCAL_CFLAGS+=
LOCAL_CPPFLAGS+=-I${R}/src
LOCAL_LDFLAGS+=
LOCAL_LIBADD+=${LIBMOSQ_COMMON}

# Objects for this plugin only, built from source in this directory
OBJS = \
	password_check.o \
	password_parse.o \
	plugin.o

# Objects from e.g. the common directory that are not in this directory
OBJS_EXTERNAL =

all : binary

include ${R}/plugins/plugin.mk
