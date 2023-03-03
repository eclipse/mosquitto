R=../../..
.PHONY: all test clean reallyclean

CFLAGS=-I${R}/include -Wall -Werror

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
	plugin_control.c \
	plugin_evt_message_in.c \
	plugin_evt_message_out.c \
	plugin_evt_psk_key.c \
	plugin_evt_subscribe.c \
	plugin_evt_tick.c \
	plugin_evt_unsubscribe.c

PLUGINS = ${PLUGIN_SRC:.c=.so}

SRC = \
	08-tls-psk-pub.c \
	08-tls-psk-bridge.c

TESTS = ${SRC:.c=.test}


all : ${PLUGINS} ${TESTS}

${PLUGINS} : %.so: %.c
	$(CC) ${CFLAGS} -fPIC -shared $< -o $@


${TESTS} : %.test: %.c
	$(CC) ${CFLAGS} $< -o $@ ${R}/lib/libmosquitto.so.1


reallyclean : clean
	-rm -f *.orig

clean :
	rm -f *.so *.test
