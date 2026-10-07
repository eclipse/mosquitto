R=../../..
include ${R}/config.mk

.PHONY: all test clean reallyclean

LOCAL_CPPFLAGS+=-I${R}/include
LOCAL_CFLAGS+=-Wall -Werror
LOCAL_LDFLAGS+=-fPIC -shared

PLUGIN_SRC = \
	auth_plugin_acl.c \
	auth_plugin_acl_change.c \
	auth_plugin_acl_sub_denied.c \
	auth_plugin_context_params.c \
	auth_plugin_delayed.c \
	auth_plugin_extended_multiple.c \
	auth_plugin_extended_reauth.c \
	auth_plugin_extended_single.c \
	auth_plugin_extended_single2.c \
	auth_plugin_id_change.c \
	auth_plugin_msg_params.c \
	auth_plugin_publish.c \
	auth_plugin_pwd.c \
	auth_plugin_v2.c \
	auth_plugin_v3.c \
	auth_plugin_v4.c \
	auth_plugin_v5.c \
	auth_plugin_v5_control.c \
	bad_vnone_1.c \
	bad_v1.c \
	bad_v2_1.c \
	bad_v2_2.c \
	bad_v2_3.c \
	bad_v2_4.c \
	bad_v2_5.c \
	bad_v2_6.c \
	bad_v2_7.c \
	bad_v3_1.c \
	bad_v3_2.c \
	bad_v3_3.c \
	bad_v3_4.c \
	bad_v3_5.c \
	bad_v3_6.c \
	bad_v3_7.c \
	bad_v4_1.c \
	bad_v4_2.c \
	bad_v4_3.c \
	bad_v4_4.c \
	bad_v5_1.c \
	bad_v6.c \
	kick_last_client.c \
	plugin_control.c \
	plugin_evt_client_offline.c \
	plugin_evt_message_in.c \
	plugin_evt_message_out.c \
	plugin_evt_psk_key.c \
	plugin_evt_reload.c \
	plugin_evt_subscribe.c \
	plugin_evt_tick.c \
	plugin_evt_unsubscribe.c \
	plugin_evt_persist_client_update.c \
	plugin_load_acl.c \
	plugin_load_extended_auth.c

PLUGINS = ${PLUGIN_SRC:.c=.so}

SRC = \
	08-tls-psk-pub.c \
	08-tls-psk-bridge.c

TESTS = ${SRC:.c=.exe}


all : ${PLUGINS} ${TESTS}

${PLUGINS} : %.so: %.c
	$(CC) $(LOCAL_CPPFLAGS) ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} $< -o $@


${TESTS} : %.exe: %.c
	$(CC) $(LOCAL_CPPFLAGS) ${LOCAL_CFLAGS} $< -o $@ ${LIBMOSQ}


reallyclean : clean
	-rm -f *.orig

clean :
	rm -f *.so *.test
