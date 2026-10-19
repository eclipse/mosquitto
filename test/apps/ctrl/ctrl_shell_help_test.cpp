/*
Copyright (c) 2022 Cedalo GmbH
*/

// clang-format off
#include "mosquitto_internal.h" // keep this at the top for `#define uthash_free`
#include "ctrl_shell.h"
#include "ctrl_shell_internal.h"
#include "json_help.h"
// clang-format on
#include <gmock/gmock-actions.h>
#include <gtest/gtest.h>

#include <cstring>

#include "ctrl_shell_mock.hpp"
#include "editline_mock.hpp"
#include "libmosquitto_mock.hpp"
#include "pthread_mock.hpp"

namespace t = testing;

class CtrlShellHelpTest : public ::t::Test
{
public:
	::t::StrictMock<CtrlShellMock> ctrl_shell_mock_{};
	::t::StrictMock<EditLineMock> editline_mock_{};
	::t::StrictMock<LibMosquittoMock> libmosquitto_mock_{};
	::t::StrictMock<PThreadMock> pthread_mock_{};
	LIBMOSQ_CB_connect on_connect{};
	LIBMOSQ_CB_message on_message{};


	void expect_setup(struct mosq_config *config)
	{
		editline_mock_.reset();
		EXPECT_CALL(editline_mock_, rl_bind_key(t::Eq('\t'), t::_));
		EXPECT_CALL(editline_mock_, add_history(t::_)).WillRepeatedly(t::Return(0));
		EXPECT_CALL(editline_mock_, clear_history()).Times(t::AnyNumber());
		config->no_colour = true;

		EXPECT_CALL(ctrl_shell_mock_, ctrl_shell__output(t::StartsWith("mosquitto_ctrl shell v")));
	}


	void expect_connect(struct mosquitto *mosq, const char *host, int port)
	{
		EXPECT_CALL(libmosquitto_mock_, mosquitto_new(t::Eq(nullptr), t::Eq(true), t::Eq(nullptr)))
			.WillOnce(t::Return(mosq));
		EXPECT_CALL(libmosquitto_mock_, mosquitto_int_option(t::Eq(mosq), MOSQ_OPT_PROTOCOL_VERSION, 5));
		EXPECT_CALL(libmosquitto_mock_, mosquitto_subscribe_callback_set(t::Eq(mosq), t::_));
		EXPECT_CALL(libmosquitto_mock_, mosquitto_publish_v5_callback_set(t::Eq(mosq), t::_));
		EXPECT_CALL(libmosquitto_mock_, mosquitto_connect(t::Eq(mosq), t::StrEq(host), port, 60));
		EXPECT_CALL(libmosquitto_mock_, mosquitto_loop_start(t::Eq(mosq)));

		EXPECT_CALL(libmosquitto_mock_, mosquitto_connect_callback_set(t::Eq(mosq), t::A<LIBMOSQ_CB_connect>()))
			.WillRepeatedly(t::SaveArg<1>(&this->on_connect));
		EXPECT_CALL(libmosquitto_mock_, mosquitto_message_callback_set(t::Eq(mosq), t::A<LIBMOSQ_CB_message>()))
			.WillOnce(t::SaveArg<1>(&this->on_message));
	}


	void expect_disconnect(struct mosquitto *mosq)
	{
		EXPECT_CALL(libmosquitto_mock_, mosquitto_disconnect(t::Eq(mosq)));
		EXPECT_CALL(libmosquitto_mock_, mosquitto_loop_stop(t::Eq(mosq), false));
		EXPECT_CALL(libmosquitto_mock_, mosquitto_destroy(t::Eq(mosq)));
	}


	void expect_outputs(const char **outputs, size_t count)
	{
		for(size_t i=0; i<count; i++){
			EXPECT_CALL(ctrl_shell_mock_, ctrl_shell__output(t::StrEq(outputs[i]))).Times(t::AtLeast(1));
		}
	}
};

TEST_F(CtrlShellHelpTest, PreConnectHelp)
{
	mosq_config config{};

	expect_setup(&config);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("> ")))
		.WillOnce(t::Return(strdup("help")))
		.WillOnce(t::Return(strdup("help auth")))
		.WillOnce(t::Return(strdup("help connect")))
		.WillOnce(t::Return(strdup("help exit")))
		.WillOnce(t::Return(strdup("help help")))
		.WillOnce(t::Return(strdup("help unknown")))
		.WillOnce(t::Return(strdup("unknown")))
		.WillOnce(t::Return(nullptr));

	const char *outputs[] = {
		"This is the mosquitto_ctrl interactive shell, for controlling aspects of a mosquitto broker.\n",
		"Find help on a command using 'help <command>'\n",
		"Press tab multiple times to find currently available commands.\n\n",
		"\n",
		"Example workflow:\n\n",
		"> auth\n",
		"username: admin\n",
		"password:\n",
		"> connect mqtt://localhost\n",
		"mqtt://localhost:1883> dynsec\n",
		"mqtt://localhost:1883|dynsec> createGroup newgroup\n",
		"OK\n\n",

		"auth [username]\n",
		"\nSet a username and password prior to connecting to a broker.\n",     /* help auth */
		"connect\n",
		"connect mqtt://hostname[:port]\n",
		"connect mqtts://hostname[:port]\n",
		"connect ws://hostname[:port]\n",
		"connect wss://hostname[:port]\n",
		"\nConnect to a broker using the provided transport and port.\n",
		"If no URL is provided, connects to mqtt://localhost:1883\n",     /* help connect */
		"exit\n",
		"\nQuit the program\n",     /* help exit */
		"help <command>\n",
		"\nFind help on a command using 'help <command>'\n",
		"Press tab multiple times to find currently available commands.\n",     /* help help */
		"Unknown command 'unknown'\n", /* help unknown */
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
}

TEST_F(CtrlShellHelpTest, Exit)
{
	mosq_config config{};

	expect_setup(&config);

	char *s = strdup("exit");
	EXPECT_CALL(editline_mock_, readline(t::StrEq("> ")))
		.WillOnce(t::Return(s));
	EXPECT_CALL(ctrl_shell_mock_, ctrl_shell__output(t::StrEq("\n")));

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellHelpTest, Connect)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;
	char buf[200];

	expect_setup(&config);
	expect_connect(&mosq, host, port);

	snprintf(buf, sizeof(buf), "connect mqtt://%s:%d", host, port);
	char *s_conn = strdup(buf);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("> ")))
		.WillOnce(t::Return(s_conn));

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883> ")))
		.WillOnce(t::Return(nullptr));

	/* This is a hacky way of working around the async mqtt CONNECT/CONNACK which we don't directly control. */
	EXPECT_CALL(pthread_mock_, pthread_cond_timedwait(t::_, t::_, t::_))
		.WillOnce(t::Invoke([this, &mosq](pthread_cond_t *, pthread_mutex_t *, const struct timespec *){
		this->on_connect(&mosq, nullptr, 0);
		data.response_received = true;
		return 0;
	}));
	EXPECT_CALL(ctrl_shell_mock_, ctrl_shell__output(t::StrEq("\n")));

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellHelpTest, PostConnectHelp)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;
	char buf[200];

	expect_setup(&config);
	expect_connect(&mosq, host, port);

	snprintf(buf, sizeof(buf), "connect mqtt://%s:%d", host, port);
	char *s_conn = strdup(buf);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("> ")))
		.WillOnce(t::Return(s_conn))
		.WillOnce(t::Return(strdup("exit")));

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883> ")))
		.WillOnce(t::Return(strdup("help")))
		.WillOnce(t::Return(strdup("help dynsec")))
		.WillOnce(t::Return(strdup("help broker")))
		.WillOnce(t::Return(strdup("help disconnect")))
		.WillOnce(t::Return(strdup("help exit")))
		.WillOnce(t::Return(strdup("help help")))
		.WillOnce(t::Return(strdup("help unknown")))
		.WillOnce(t::Return(strdup("unknown")))
		.WillOnce(t::Return(strdup("disconnect")));

	/* This is a hacky way of working around the async mqtt send/receive which we don't directly control.
	 * Each send starts a wait which times out after two seconds. We use that call to produce the effect we want.
	 */
	EXPECT_CALL(pthread_mock_, pthread_cond_timedwait(t::_, t::_, t::_))
		.WillOnce(t::Invoke([this, &mosq](pthread_cond_t *, pthread_mutex_t *, const struct timespec *){
		this->on_connect(&mosq, nullptr, 0);
		data.response_received = true;
		return 0;
	}));

	const char *outputs[] = {
		"This is the mosquitto_ctrl interactive shell, for controlling aspects of a mosquitto broker.\n",
		"Find help on a command using 'help <command>'\n",
		"Press tab multiple times to find currently available commands.\n\n",
		"Example workflow:\n\n",
		"> auth\n",
		"username: admin\n",
		"password:\n",
		"> connect mqtt://localhost\n",
		"mqtt://localhost:1883> dynsec\n",
		"mqtt://localhost:1883|dynsec> createGroup newgroup\n",
		"OK\n\n",
		"\n",

		"dynsec\n",
		"\nStart the dynamic-security control mode.\n",     /* help dynsec */
		"broker\n",
		"\nStart the broker control mode.\n",     /* help broker */
		"disconnect\n",
		"\nDisconnect from the broker\n",     /* help disconnect */
		"exit\n",
		"\nQuit the program\n",     /* help exit */
		"help <command>\n",
		"\nFind help on a command using 'help <command>'\n",
		"Press tab multiple times to find currently available commands.\n",     /* help help */
		"Unknown command 'unknown'\n", /* help unknown */
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	expect_disconnect(&mosq);

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellHelpTest, BrokerHelp)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;
	char buf[200];

	expect_setup(&config);
	expect_connect(&mosq, host, port);

	snprintf(buf, sizeof(buf), "connect mqtt://%s:%d", host, port);
	char *s_conn = strdup(buf);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("> ")))
		.WillOnce(t::Return(s_conn))
		.WillOnce(t::Return(strdup("exit")));

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883> ")))
		.WillOnce(t::Return(strdup("broker")))
		.WillOnce(t::Return(strdup("disconnect")));
	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|broker> ")))
		.WillOnce(t::Return(strdup("help "))) // Extra space on end to invoke trim
		.WillOnce(t::Return(strdup("help listPlugins")))
		.WillOnce(t::Return(strdup("help listListeners")))
		.WillOnce(t::Return(strdup("help disconnect")))
		.WillOnce(t::Return(strdup("help help")))
		.WillOnce(t::Return(strdup("help return")))
		.WillOnce(t::Return(strdup("help exit")))
		.WillOnce(t::Return(strdup("help unknown")))
		.WillOnce(t::Return(strdup("unknown")))
		.WillOnce(t::Return(strdup("return")));

	EXPECT_CALL(libmosquitto_mock_, mosquitto_subscribe(t::_, nullptr, t::StrEq("$CONTROL/broker/v1/response"), 1))
		.WillOnce(t::Return(0));

	/* This is a hacky way of working around the async mqtt send/receive which we don't directly control.
	 * Each send starts a wait which times out after two seconds. We use that call to produce the effect we want.
	 */
	EXPECT_CALL(pthread_mock_, pthread_cond_timedwait(t::_, t::_, t::_))
		.WillOnce(t::Invoke([this, &mosq](pthread_cond_t *, pthread_mutex_t *, const struct timespec *){
		this->on_connect(&mosq, nullptr, 0);
		data.response_received = true;
		return 0;
	}))
		.WillOnce(t::Invoke([this, &mosq](pthread_cond_t *, pthread_mutex_t *, const struct timespec *){
		mosquitto_message msg{};
		this->on_message(&mosq, nullptr, &msg);
		data.response_received = true;
		return 0;
	}));

	const char *outputs[] = {
		"This is the mosquitto_ctrl interactive shell, for controlling aspects of a mosquitto broker.\n",
		"You are in broker mode, for controlling some core broker functionality.\n",
		"Use 'return' to leave this mode.\n",
		"Find help on a command using 'help <command>'\n",
		"Press tab multiple times to find currently available commands.\n\n",
		"\n",
		"Unknown command 'unknown'\n",

		"listPlugins\n",
		"\nLists currently loaded plugins.\n",
		"listListeners\n",
		"\nLists current listeners.\n",
		"disconnect\n",
		"\nDisconnect from the broker\n",     /* help disconnect */
		"return\n",
		"\nLeave broker mode.\n",
		"exit\n",
		"\nQuit the program\n",     /* help exit */
		"help <command>\n",
		"\nFind help on a command using 'help <command>'\n",
		"Press tab multiple times to find currently available commands.\n",     /* help help */
		"Invalid response from broker.\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	expect_disconnect(&mosq);

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellHelpTest, DynsecHelp)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;
	char buf[200];

	expect_setup(&config);
	expect_connect(&mosq, host, port);

	snprintf(buf, sizeof(buf), "connect mqtt://%s:%d", host, port);
	char *s_conn = strdup(buf);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("> ")))
		.WillOnce(t::Return(s_conn));

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883> ")))
		.WillOnce(t::Return(strdup("dynsec")))
		.WillOnce(t::Return(nullptr));
	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("help")))
		.WillOnce(t::Return(strdup("help addClientRole")))
		.WillOnce(t::Return(strdup("help addGroupClient")))
		.WillOnce(t::Return(strdup("help addGroupRole")))
		.WillOnce(t::Return(strdup("help addRoleACL")))
		.WillOnce(t::Return(strdup("help createClient")))
		.WillOnce(t::Return(strdup("help createGroup")))
		.WillOnce(t::Return(strdup("help createRole")))
		.WillOnce(t::Return(strdup("help deleteClient")))
		.WillOnce(t::Return(strdup("help deleteGroup")))
		.WillOnce(t::Return(strdup("help deleteRole")))
		.WillOnce(t::Return(strdup("help disableClient")))
		.WillOnce(t::Return(strdup("help enableClient")))
		.WillOnce(t::Return(strdup("help getAnonymousGroup")))
		.WillOnce(t::Return(strdup("help getClient")))
		.WillOnce(t::Return(strdup("help getDetails")))
		.WillOnce(t::Return(strdup("help getDefaultACLAccess")))
		.WillOnce(t::Return(strdup("help getGroup")))
		.WillOnce(t::Return(strdup("help getRole")))
		.WillOnce(t::Return(strdup("help listClients")))
		.WillOnce(t::Return(strdup("help listGroups")))
		.WillOnce(t::Return(strdup("help listRoles")))
		.WillOnce(t::Return(strdup("help removeClientRole")))
		.WillOnce(t::Return(strdup("help removeGroupClient")))
		.WillOnce(t::Return(strdup("help removeGroupRole")))
		.WillOnce(t::Return(strdup("help removeRoleACL")))
		.WillOnce(t::Return(strdup("help setAnonymousGroup")))
		.WillOnce(t::Return(strdup("help setClientId")))
		.WillOnce(t::Return(strdup("help setClientPassword")))
		.WillOnce(t::Return(strdup("help setDefaultACLAccess")))
		.WillOnce(t::Return(strdup("help modifyClient")))
		.WillOnce(t::Return(strdup("help modifyGroup")))
		.WillOnce(t::Return(strdup("help modifyRole")))
		.WillOnce(t::Return(strdup("help disconnect")))
		.WillOnce(t::Return(strdup("help help")))
		.WillOnce(t::Return(strdup("help return")))
		.WillOnce(t::Return(strdup("help exit")))
		.WillOnce(t::Return(strdup("help unknown")))
		.WillOnce(t::Return(strdup("unknown")))
		.WillOnce(t::Return(strdup("return")));

	EXPECT_CALL(libmosquitto_mock_, mosquitto_subscribe(t::_, nullptr, t::StrEq("$CONTROL/dynamic-security/v1/response"), 1))
		.WillOnce(t::Return(0));

	/* This is a hacky way of working around the async mqtt send/receive which we don't directly control.
	 * Each send starts a wait which times out after two seconds. We use that call to produce the effect we want.
	 */
	EXPECT_CALL(pthread_mock_, pthread_cond_timedwait(t::_, t::_, t::_))
		.WillOnce(t::Invoke([this, &mosq](pthread_cond_t *, pthread_mutex_t *, const struct timespec *){
		this->on_connect(&mosq, nullptr, 0); data.response_received = true; return 0;
	}))
		.WillOnce(t::Invoke([this, &mosq](pthread_cond_t *, pthread_mutex_t *, const struct timespec *){
		mosquitto_message msg{};
		this->on_message(&mosq, nullptr, &msg); data.response_received = true; return 0;
	}))
		.WillOnce(t::Invoke([this, &mosq](pthread_cond_t *, pthread_mutex_t *, const struct timespec *){
		mosquitto_message msg{};
		this->on_message(&mosq, nullptr, &msg); data.response_received = true; return 0;
	}))
		.WillOnce(t::Invoke([this, &mosq](pthread_cond_t *, pthread_mutex_t *, const struct timespec *){
		mosquitto_message msg{};
		this->on_message(&mosq, nullptr, &msg); data.response_received = true; return 0;
	}))
		.WillOnce(t::Invoke([this, &mosq](pthread_cond_t *, pthread_mutex_t *, const struct timespec *){
		mosquitto_message msg{};
		this->on_message(&mosq, nullptr, &msg); data.response_received = true; return 0;
	}))
		.WillOnce(t::Invoke([this, &mosq](pthread_cond_t *, pthread_mutex_t *, const struct timespec *){
		mosquitto_message msg{};
		this->on_message(&mosq, nullptr, &msg); data.response_received = true; return 0;
	}))
		.WillOnce(t::Invoke([this, &mosq](pthread_cond_t *, pthread_mutex_t *, const struct timespec *){
		mosquitto_message msg{};
		this->on_message(&mosq, nullptr, &msg); data.response_received = true; return 0;
	}))
		.WillOnce(t::Invoke([this, &mosq](pthread_cond_t *, pthread_mutex_t *, const struct timespec *){
		mosquitto_message msg{};
		this->on_message(&mosq, nullptr, &msg); data.response_received = true; return 0;
	}));

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listClients\"}]}"), 1, false))
		.WillOnce(t::Return(0));

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listGroups\"}]}"), 1, false))
		.WillOnce(t::Return(0));

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listRoles\"}]}"), 1, false))
		.WillOnce(t::Return(0));

	const char *outputs[] = {
		"This is the mosquitto_ctrl interactive shell, for controlling aspects of a mosquitto broker.\n",
		"You are in dynsec mode, for controlling the dynamic-security clients, groups, and roles used in authentication and authorisation.\n",
		"Use 'return' to leave dynsec mode.\n",
		"Find help on a command using 'help <command>'\n",
		"Press tab multiple times to find currently available commands.\n\n",
		"\n",
		"Unknown command 'unknown'\n",

		"addClientRole <username> <rolename>\n",
		"\nAdds a role directly to a client.\n",
		"addGroupClient <groupname> <username>\n",
		"\nAdds a client to a group.\n",
		"addGroupRole <groupname> <rolename>\n",
		"\nAdds a role to a group.\n",
		"addRoleACL <rolename> publishClientReceive allow|deny [priority] <topic>\n",
		"addRoleACL <rolename> publishClientSend allow|deny [priority] <topic>\n",
		"addRoleACL <rolename> subscribeLiteral allow|deny [priority] <topic>\n",
		"addRoleACL <rolename> subscribePattern allow|deny [priority] <topic>\n",
		"addRoleACL <rolename> unsubscribeLiteral allow|deny [priority] <topic>\n",
		"addRoleACL <rolename> unsubscribePattern allow|deny [priority] <topic>\n",
		"\nAdds an ACL to a role, with an optional priority.\n",
		"\nACLs of a specific type within a role are processed in order from highest to lowest priority with the first matching ACL applying.\n",
		"createClient <username> [password [clientid]]\n",
		"\nCreate a client with password and optional client id.\n",
		"createGroup <groupname>\n",
		"\nCreate a new group.\n",
		"createRole <rolename>\n",
		"\nCreate a new role.\n",
		"deleteClient <username>\n",
		"\nDelete a client\n",
		"deleteGroup <groupname>\n",
		"\nDelete a group\n",
		"deleteRole <rolename>\n",
		"\nDelete a role\n",
		"disableClient <username>\n",
		"\nDisable a client. This client will not be able to log in, and will be kicked if it has an existing session.\n",
		"enableClient <username>\n",
		"\nEnable a client. Disabled clients are unable to log in.\n",
		"getAnonymousGroup\n",
		"\nPrint the group configured as the anonymous group.\n",
		"getClient <username>\n",
		"\nPrint details of a client and its groups and direct roles.\n",
		"getDefaultACLAccess\n",
		"\nPrint the default allow/deny values for the different classes of ACL.\n",
		"getDetails\n",
		"\nPrint details including the client, group, and role count, and the current change index.\n",
		"getGroup <groupname>\n",
		"\nPrint details of a group and its roles.\n",
		"getRole <rolename>\n",
		"\nPrint details of a role and its ACLs.\n",
		"listClients [count [offset]]\n",
		"\nPrint a list of clients configured in the dynsec plugin, with an optional total count and list offset.\n",
		"listGroups [count [offset]]\n",
		"\nPrint a list of groups configured in the dynsec plugin, with an optional total count and list offset.\n",
		"listRoles [count [offset]]\n",
		"\nPrint a list of roles configured in the dynsec plugin, with an optional total count and list offset.\n",
		"removeClientRole <username> <rolename>\n",
		"\nRemoves a role from a client, where the role was directly attached to the client.\n",
		"removeGroupClient <groupname> <username>\n",
		"\nRemoves a client from a group.\n",
		"removeGroupRole <groupname> <rolename>\n",
		"\nRemoves a role from a group.\n",
		"removeRoleACL <rolename> publishClientReceive <topic>\n",
		"removeRoleACL <rolename> publishClientSend <topic>\n",
		"removeRoleACL <rolename> subscribeLiteral <topic>\n",
		"removeRoleACL <rolename> subscribePattern <topic>\n",
		"removeRoleACL <rolename> unsubscribeLiteral <topic>\n",
		"removeRoleACL <rolename> unsubscribePattern <topic>\n",
		"\nRemoves an ACL from a role.\n",
		"setAnonymousGroup <groupname>\n",
		"\nSets the anonymous group to a new group.\n",
		"setClientId <username>\n",
		"setClientId <username> <clientid>\n",
		"\nSets or clears the clientid associated with a client. If a client has a clientid, all three of username, password, and clientid must match for a client to be able to authenticate.\n",
		"setClientPassword <username> [password]\n",
		"\nSets a new password for a client.\n",
		"setDefaultACLAccess publishClientReceive allow|deny\n",
		"setDefaultACLAccess publishClientSend allow|deny\n",
		"setDefaultACLAccess subscribe allow|deny\n",
		"setDefaultACLAccess unsubscribe allow|deny\n",
		"\nSets the default ACL access to use for an ACL type. The default access will be applied if no other ACL rules match.\n",
		"Setting a rule to 'allow' means that if no ACLs match, it will be accepted.\n",
		"Setting a rule to 'deny' means that if no ACLs match, it will be denied.\n",
		"modifyClient <username> textName <textname>\n",
		"modifyClient <username> textDescription <textdescription>\n",
		"\nModify the text name or text description for a client.\n",
		"These are free-text fields for your own use.\n",
		"modifyGroup <groupname> textName <textname>\n",
		"modifyGroup <groupname> textDescription <textdescription>\n",
		"\nModify the text name or text description for a group.\n",
		"modifyRole <rolename> textName <textname>\n",
		"modifyRole <rolename> textDescription <textdescription>\n",
		"modifyRole <rolename> allowWildcardSubs true|false\n",
		"modifyRole <rolename> maxPublishSize <bytes, or 0 to disable>\n",
		"modifyRole <rolename> publishRateLimit {\"messages\":50,\"perSeconds\":1,\"burst\":200}|null\n",
		"\nModify the text name or text description for a role.\n",

		"disconnect\n",
		"\nDisconnect from the broker\n",     /* help disconnect */
		"return\n",
		"\nLeave dynsec mode.\n",
		"exit\n",
		"\nQuit the program\n",     /* help exit */
		"help <command>\n",
		"\nFind help on a command using 'help <command>'\n", "Press tab multiple times to find currently available commands.\n",     /* help help */
		"Invalid response from broker.\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
}
