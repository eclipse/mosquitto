R=../..
include ${R}/config.mk

PLUGIN_NAME=mosquitto_persist_sqlite
LOCAL_CFLAGS+=
LOCAL_CPPFLAGS+=-I${R}/src/ -I${R}/plugins/common
LOCAL_LIBADD+=-lsqlite3 ${LIBMOSQ_COMMON}
LOCAL_LDFLAGS+=

OBJS = \
	base_msgs.o \
	clients.o \
	client_msgs.o \
	common.o \
	init.o \
	plugin.o \
	restore.o \
	retain_msgs.o \
	subscriptions.o \
	tick.o \
	will.o

OBJS_EXTERNAL = \
	json_help.o

ALL_DEPS:= binary

all : ${ALL_DEPS}

json_help.o : ${R}/common/json_help.c ${R}/common/json_help.h
	${CROSS_COMPILE}${CC} $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

EXTRA_DEPS:=persist_sqlite.h

include ${R}/plugins/plugin.mk
