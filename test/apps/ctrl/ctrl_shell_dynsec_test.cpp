/*
Copyright (c) 2022 Cedalo GmbH
*/

// clang-format off
#include "mosquitto_internal.h" // keep this at the top for `#define uthash_free`
#include "ctrl_shell.h"
#include "ctrl_shell_internal.h"
#include "json_help.h"
#include "utlist.h"
// clang-format on
#include <gmock/gmock-actions.h>
#include <gtest/gtest.h>

#include <cstring>

#include "ctrl_shell_mock.hpp"
#include "editline_mock.hpp"
#include "libmosquitto_mock.hpp"
#include "pthread_mock.hpp"

namespace t = testing;

struct pending_payload {
	struct pending_payload *next, *prev;
	char payload[1024];
};

class CtrlShellDynsecTest : public ::t::Test
{
public:
	::t::StrictMock<CtrlShellMock> ctrl_shell_mock_{};
	::t::StrictMock<EditLineMock> editline_mock_{};
	::t::StrictMock<LibMosquittoMock> libmosquitto_mock_{};
	::t::StrictMock<PThreadMock> pthread_mock_{};
	LIBMOSQ_CB_connect on_connect{};
	LIBMOSQ_CB_message on_message{};
	struct pending_payload *pending_payloads = nullptr;


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


	void expect_request_response(struct mosquitto *mosq, const char *request, const char *respons)
	{
		struct pending_payload *pp = (struct pending_payload *)calloc(1, sizeof(struct pending_payload));
		snprintf(pp->payload, sizeof(pp->payload), "%s", respons);

		EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
				t::StrEq(request), 1, false))
			.WillOnce(t::Invoke([this, pp](){
			DL_APPEND(this->pending_payloads, pp);
			return 0;
		}));
	}


	void expect_request_response_success(struct mosquitto *mosq, const char *request, const char *command)
	{
		char response[100];
		snprintf(response, sizeof(response), "{\"responses\":[{\"command\":\"%s\"}]}", command);
		expect_request_response(mosq, request, response);
	}


	void expect_request_response_empty(struct mosquitto *mosq, const char *command)
	{
		char request[100];
		char response[100];

		snprintf(request, sizeof(request), "{\"commands\":[{\"command\":\"%s\"}]}", command);
		snprintf(response, sizeof(response), "{\"responses\":[{\"command\":\"%s\",\"data\":{}}]}", command);

		EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
				t::StrEq(request), 1, false))
			.WillOnce(t::Invoke([this, command](){
			append_empty_response(command);
			return 0;
		}));
	}


	void append_response(const char *response)
	{
		struct pending_payload *pp = (struct pending_payload *)calloc(1, sizeof(struct pending_payload));
		snprintf(pp->payload, sizeof(pp->payload), "%s", response);
		DL_APPEND(this->pending_payloads, pp);
	}


	void append_empty_response(const char *command)
	{
		struct pending_payload *pp = (struct pending_payload *)calloc(1, sizeof(struct pending_payload));
		snprintf(pp->payload, sizeof(pp->payload),
				"{\"responses\":[{\"command\":\"%s\",\"data\":{}}]}", command);
		DL_APPEND(this->pending_payloads, pp);
	}


	void expect_single_lists(struct mosquitto *mosq)
	{
		expect_request_response_empty(mosq, "listClients");
		expect_request_response_empty(mosq, "listGroups");
		expect_request_response_empty(mosq, "listRoles");
	}


	void expect_dynsec(const char *host, int port)
	{
		char buf[200];
		snprintf(buf, sizeof(buf), "connect mqtt://%s:%d", host, port);
		char *s_conn = strdup(buf);

		EXPECT_CALL(editline_mock_, readline(t::StrEq("> ")))
			.WillOnce(t::Return(s_conn));

		EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883> ")))
			.WillOnce(t::Return(strdup("dynsec")));

		EXPECT_CALL(libmosquitto_mock_, mosquitto_subscribe(t::_, nullptr, t::StrEq("$CONTROL/dynamic-security/v1/response"), 1))
			.WillOnce(t::Return(0));
	}


	void expect_connect_and_messages(struct mosquitto *mosq)
	{
		/* This is a hacky way of working around the async mqtt send/receive which we don't directly control.
			    * Each send starts a wait which times out after two seconds. We use that call to produce the effect we want.
			    */
		EXPECT_CALL(pthread_mock_, pthread_cond_timedwait(t::_, t::_, t::_))
			.WillOnce(t::Invoke([this, mosq](pthread_cond_t *, pthread_mutex_t *, const struct timespec *){
			this->on_connect(mosq, nullptr, 0);
			data.response_received = true;
			return 0;
		}))
			.WillRepeatedly(t::Invoke([this, mosq](pthread_cond_t *, pthread_mutex_t *, const struct timespec *){
			mosquitto_message msg{};
			struct pending_payload *pp = this->pending_payloads;
			if(pp){
				DL_DELETE(pending_payloads, pp);
				msg.payload = pp->payload;
				msg.payloadlen = (int)strlen((char *)msg.payload);
				this->on_message(mosq, nullptr, &msg);
				free(pp);
			}
			data.response_received = true;
			return 0;
		}));
	}


	void expect_generic_arg1(const char *command, const char *itemlabel, const char *itemvalue)
	{
		mosq_config config{};
		mosquitto mosq{};
		const char host[] = "localhost";
		int port = 1883;
		char line[200];
		char payload[500];

		expect_setup(&config);
		expect_connect(&mosq, host, port);
		expect_dynsec(host, port);

		snprintf(line, sizeof(line), "%s %s", command, itemvalue);
		EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
			.WillOnce(t::Return(strdup(line)))
			.WillOnce(t::Return(strdup("exit")));

		expect_connect_and_messages(&mosq);
		expect_single_lists(&mosq);

		snprintf(payload, sizeof(payload),
				"{\"commands\":[{\"command\":\"%s\",\"%s\":\"%s\"}]}",
				command, itemlabel, itemvalue);
		expect_request_response_success(&mosq, payload, command);

		const char *outputs[] = {
			"OK\n",
			"\n",
		};
		expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

		ctrl_shell__main(&config);
	}


	void expect_generic_arg1_with_list_update(const char *command, const char *itemlabel, const char *itemvalue, const char *listcmd)
	{
		mosq_config config{};
		mosquitto mosq{};
		const char host[] = "localhost";
		int port = 1883;
		char line[200];
		char request[500];

		expect_setup(&config);
		expect_connect(&mosq, host, port);
		expect_dynsec(host, port);

		snprintf(line, sizeof(line), "%s %s", command, itemvalue);
		EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
			.WillOnce(t::Return(strdup(line)))
			.WillOnce(t::Return(strdup("exit")));

		expect_connect_and_messages(&mosq);
		expect_single_lists(&mosq);

		snprintf(request, sizeof(request),
				"{\"commands\":[{\"command\":\"%s\",\"%s\":\"%s\"}]}",
				command, itemlabel, itemvalue);
		expect_request_response_success(&mosq, request, command);

		expect_request_response_empty(&mosq, listcmd);

		const char *outputs[] = {
			"OK\n",
			"\n",
		};
		expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

		ctrl_shell__main(&config);
	}


	void expect_generic_arg1_with_error(const char *command, const char *itemlabel)
	{
		mosq_config config{};
		mosquitto mosq{};
		const char host[] = "localhost";
		int port = 1883;
		char line[200];
		char error[200];

		expect_setup(&config);
		expect_connect(&mosq, host, port);
		expect_dynsec(host, port);

		snprintf(line, sizeof(line), "%s", command);
		EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
			.WillOnce(t::Return(strdup(line)))
			.WillOnce(t::Return(strdup("exit")));

		expect_connect_and_messages(&mosq);
		expect_single_lists(&mosq);

		snprintf(error, sizeof(error), "%s %s\n", command, itemlabel);
		const char *outputs[] = {
			error,
			"\n",
		};
		expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

		ctrl_shell__main(&config);
	}


	void expect_generic_arg2(const char *command, const char *itemlabel1, const char *itemvalue1, const char *itemlabel2, const char *itemvalue2)
	{
		mosq_config config{};
		mosquitto mosq{};
		const char host[] = "localhost";
		int port = 1883;
		char line[200];
		char payload[500];

		expect_setup(&config);
		expect_connect(&mosq, host, port);
		expect_dynsec(host, port);

		snprintf(line, sizeof(line), "%s %s %s", command, itemvalue1, itemvalue2);
		EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
			.WillOnce(t::Return(strdup(line)))
			.WillOnce(t::Return(strdup("exit")));

		expect_connect_and_messages(&mosq);
		expect_single_lists(&mosq);

		snprintf(payload, sizeof(payload),
				"{\"commands\":[{\"command\":\"%s\","
				"\"%s\":\"%s\","
				"\"%s\":\"%s\""
				"}]}",
				command, itemlabel1, itemvalue1, itemlabel2, itemvalue2);
		expect_request_response_success(&mosq, payload, command);

		const char *outputs[] = {
			"OK\n",
			"\n",
		};
		expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

		ctrl_shell__main(&config);
	}


	void expect_send_set_acl_default_access(const char *acltype)
	{
		mosq_config config{};
		mosquitto mosq{};
		const char host[] = "localhost";
		int port = 1883;
		char buf[500];

		expect_setup(&config);
		expect_connect(&mosq, host, port);
		expect_dynsec(host, port);

		snprintf(buf, sizeof(buf), "setDefaultACLAccess %s allow", acltype);
		EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
			.WillOnce(t::Return(strdup(buf)))
			.WillOnce(t::Return(strdup("exit")));

		expect_connect_and_messages(&mosq);
		expect_single_lists(&mosq);

		snprintf(buf, sizeof(buf),
				"{\"commands\":[{\"command\":\"setDefaultACLAccess\","
				"\"acls\":["
				"{"
				"\"acltype\":\"%s\","
				"\"allow\":true}]}]}",
				acltype);
		expect_request_response_success(&mosq, buf, "setDefaultACLAccess");

		const char *outputs[] = {
			"OK\n",
			"\n",
		};
		expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

		ctrl_shell__main(&config);
	}
};


TEST_F(CtrlShellDynsecTest, NoDynsec)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(pthread_mock_, pthread_cond_timedwait(t::_, t::_, t::_))
		.WillOnce(t::Invoke([this, &mosq](pthread_cond_t *, pthread_mutex_t *, const struct timespec *){
		this->on_connect(&mosq, nullptr, 0);
		data.response_received = true;
		return 0;
	}))
		.WillOnce(t::Invoke([](pthread_cond_t *, pthread_mutex_t *, const struct timespec *){
		// Subscribe
		data.response_received = true;
		return 0;
	}))
		.WillOnce(t::Return(ETIMEDOUT)); // First message to dynsec fails

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listClients\"}]}"), 1, false))
		.WillOnce(t::Return(0));

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(nullptr));

	const char *outputs[] = {
		"Timed out with no response.\n",
		"Check the dynsec module is configured on the broker.\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellDynsecTest, CreateClient)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("createClient")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char *outputs[] = {
		"createClient username [password [clientid]]\n",
		"createClient username password [clientid]\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellDynsecTest, CreateClientWithPassword)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("createClient username password")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listClients\"}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_empty_response("listClients");
		return 0;
	}))
		.WillOnce(t::Invoke([this](){
		append_empty_response("listClients");
		return 0;
	}));
	expect_request_response_empty(&mosq, "listGroups");
	expect_request_response_empty(&mosq, "listRoles");

	expect_request_response_success(&mosq,
			"{\"commands\":[{\"command\":\"createClient\",\"username\":\"username\",\"password\":\"password\"}]}",
			"createClient");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellDynsecTest, CreateClientWithPasswordAndClientid)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("createClient username1 password1 clientid1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listClients\"}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_empty_response("listClients");
		return 0;
	}))
		.WillOnce(t::Invoke([this](){
		append_empty_response("listClients");
		return 0;
	}));
	expect_request_response_empty(&mosq, "listGroups");
	expect_request_response_empty(&mosq, "listRoles");

	expect_request_response_success(&mosq,
			"{\"commands\":[{\"command\":\"createClient\",\"username\":\"username1\",\"password\":\"password1\",\"clientid\":\"clientid1\"}]}",
			"createClient");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellDynsecTest, CreateClientPasswordCliMatching)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("createClient username1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listClients\"}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_empty_response("listClients");
		return 0;
	}))
		.WillOnce(t::Invoke([this](){
		append_empty_response("listClients");
		return 0;
	}));
	expect_request_response_empty(&mosq, "listGroups");
	expect_request_response_empty(&mosq, "listRoles");

	EXPECT_CALL(ctrl_shell_mock_, ctrl_shell_fgets(t::_, t::_, t::_))
		.WillOnce(t::Invoke([](char *s, int size, FILE *){
		snprintf(s, (size_t)size, "password1");
		return s;
	}))
		.WillOnce(t::Invoke([](char *s, int size, FILE *){
		snprintf(s, (size_t)size, "password1");
		return s;
	}));

	expect_request_response_success(&mosq,
			"{\"commands\":[{\"command\":\"createClient\",\"username\":\"username1\",\"password\":\"password1\"}]}",
			"createClient");

	const char *outputs[] = {
		"password:",
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellDynsecTest, CreateClientPasswordCliNotMatching)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("createClient username")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	EXPECT_CALL(ctrl_shell_mock_, ctrl_shell_fgets(t::_, t::_, t::_))
		.WillOnce(t::Invoke([](char *s, int size, FILE *){
		snprintf(s, (size_t)size, "mypassword");
		return s;
	}))
		.WillOnce(t::Invoke([](char *s, int size, FILE *){
		snprintf(s, (size_t)size, "nomatch");
		return s;
	}));

	const char *outputs[] = {
		"password:",
		"Passwords do not match.\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellDynsecTest, CreateClientPasswordCliOneOnly)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("createClient username")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	EXPECT_CALL(ctrl_shell_mock_, ctrl_shell_fgets(t::_, t::_, t::_))
		.WillOnce(t::Invoke([](char *s, int size, FILE *){
		snprintf(s, (size_t)size, "mypassword");
		return s;
	}))
		.WillOnce(t::Return(nullptr));

	const char *outputs[] = {
		"password:",
		"No password.\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellDynsecTest, EnableClient)
{
	expect_generic_arg1("enableClient", "username", "username1");
}

TEST_F(CtrlShellDynsecTest, EnableClientMissing)
{
	expect_generic_arg1_with_error("enableClient", "username");
}

/* FIXME - Not found cases */

TEST_F(CtrlShellDynsecTest, DisableClient)
{
	expect_generic_arg1("disableClient", "username", "username1");
}

TEST_F(CtrlShellDynsecTest, DisableClientMissing)
{
	expect_generic_arg1_with_error("disableClient", "username");
}

TEST_F(CtrlShellDynsecTest, SetAnonGroup)
{
	expect_generic_arg1("setAnonymousGroup", "groupname", "groupname1");
}

TEST_F(CtrlShellDynsecTest, SetAnonGroupMissing)
{
	expect_generic_arg1_with_error("setAnonymousGroup", "groupname");
}


TEST_F(CtrlShellDynsecTest, AddClientRole)
{
	expect_generic_arg2("addClientRole", "username", "username1", "rolename", "rolename1");
}


TEST_F(CtrlShellDynsecTest, AddGroupClient)
{
	expect_generic_arg2("addGroupClient", "groupname", "groupname1", "username", "username1");
}


TEST_F(CtrlShellDynsecTest, AddGroupRole)
{
	expect_generic_arg2("addGroupRole", "groupname", "groupname1", "rolename", "rolename1");
}


TEST_F(CtrlShellDynsecTest, RemoveClientRole)
{
	expect_generic_arg2("removeClientRole", "username", "username1", "rolename", "rolename1");
}


TEST_F(CtrlShellDynsecTest, RemoveGroupClient)
{
	expect_generic_arg2("removeGroupClient", "groupname", "groupname1", "username", "username1");
}


TEST_F(CtrlShellDynsecTest, RemoveGroupRole)
{
	expect_generic_arg2("removeGroupRole", "groupname", "groupname1", "rolename", "rolename1");
}


TEST_F(CtrlShellDynsecTest, SetClientId)
{
	expect_generic_arg2("setClientId", "username", "username1", "clientid", "clientid1");
}

TEST_F(CtrlShellDynsecTest, SetDefaultACLAccessPublishClientReceive)
{
	expect_send_set_acl_default_access("publishClientReceive");
}


TEST_F(CtrlShellDynsecTest, SetDefaultACLAccessPublishClientSend)
{
	expect_send_set_acl_default_access("publishClientSend");
}


TEST_F(CtrlShellDynsecTest, SetDefaultACLAccessSubscribe)
{
	expect_send_set_acl_default_access("subscribe");
}


TEST_F(CtrlShellDynsecTest, SetDefaultACLAccessUnsubscribe)
{
	expect_send_set_acl_default_access("unsubscribe");
}


TEST_F(CtrlShellDynsecTest, SetDefaultACLAccessBadType)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("setDefaultACLAccess badtype allow")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char *outputs[] = {
		"setDefaultACLAccess acltype allow|deny\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellDynsecTest, SetDefaultACLAccessBadAllow)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("setDefaultACLAccess subscribe bad")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char *outputs[] = {
		"setDefaultACLAccess acltype allow|deny\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellDynsecTest, SetDefaultACLAccessNoAllow)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("setDefaultACLAccess publishClientSend")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char *outputs[] = {
		"setDefaultACLAccess acltype allow|deny\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
}

TEST_F(CtrlShellDynsecTest, GetDefaultACLAccess)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("getDefaultACLAccess")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{\"command\":\"getDefaultACLAccess\"}]}";
	const char response[] =
			"{\"responses\":[{\"command\":\"getDefaultACLAccess\",\"data\":{"
			"\"acls\":["
			"{\"acltype\":\"publishClientSend\",\"allow\":false},"
			"{\"acltype\":\"publishClientReceive\",\"allow\":true},"
			"{\"acltype\":\"subscribe\",\"allow\":false},"
			"{\"acltype\":\"unsubscribe\",\"allow\":true}"
			"]}}]}";

	expect_request_response(&mosq, request, response);

	const char *outputs[] = {
		"publishClientSend    deny\n",
		"publishClientReceive allow\n",
		"subscribe            deny\n",
		"unsubscribe          allow\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellDynsecTest, GetAnonymousGroup)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("getAnonymousGroup")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{\"command\":\"getAnonymousGroup\"}]}";
	const char response[] =
			"{\"responses\":[{\"command\":\"getAnonymousGroup\",\"data\":{"
			"\"group\":{\"groupname\":\"group1\"}"
			"}}]}";
	expect_request_response(&mosq, request, response);

	const char *outputs[] = {
		"group1\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellDynsecTest, GetClient)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("getClient username1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{\"command\":\"getClient\",\"username\":\"username1\"}]}";
	const char response[] =
			"{\"responses\":[{\"command\":\"getClient\",\"data\":{"
			"\"client\":{"
			"\"username\":\"username1\","
			"\"clientid\":\"clientid1\","
			"\"disabled\":true,"
			"\"textname\":\"textname1\","
			"\"textdescription\":\"textdescription1\","
			"\"roles\":["
			"{\"rolename\":\"role1\",\"priority\":1}"
			"],"
			"\"groups\":["
			"{\"groupname\":\"group1\",\"priority\":2}"
			"]}}}]}";
	expect_request_response(&mosq, request, response);

	const char *outputs[] = {
		"Username:",
		"  username1\n",
		"Clientid:",
		"  clientid1\n",
		"Text name:",
		"  textname1\n",
		"Text description:",
		"  textdescription1\n",
		"Disabled:",
		"  true\n",
		"Roles:",
		"  role1",
		"Groups:",
		"  group1",
		" (priority: ",
		"1",
		"2",
		")",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellDynsecTest, GetGroup)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("getGroup groupname1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{\"command\":\"getGroup\",\"groupname\":\"groupname1\"}]}";
	const char response[] =
			"{\"responses\":[{\"command\":\"getGroup\",\"data\":{"
			"\"group\":{"
			"\"groupname\":\"groupname1\","
			"\"textname\":\"textname1\","
			"\"textdescription\":\"textdescription1\","
			"\"roles\":["
			"{\"rolename\":\"role1\",\"priority\":1}"
			"],"
			"\"clients\":["
			"{\"username\":\"username1\",\"priority\":2}"
			"]}}}]}";
	expect_request_response(&mosq, request, response);

	const char *outputs[] = {
		"Group name:",
		"  groupname1\n",
		"Text name:",
		"  textname1\n",
		"Text description:",
		"  textdescription1\n",
		"Roles:",
		"  role1",
		"Clients:",
		"  username1",
		" (priority: ",
		"1",
		")",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
}


TEST_F(CtrlShellDynsecTest, GetRole)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("getRole rolename1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{\"command\":\"getRole\",\"rolename\":\"rolename1\"}]}";
	const char response[] =
			"{\"responses\":[{\"command\":\"getRole\",\"data\":{"
			"\"role\":{"
			"\"rolename\":\"rolename1\","
			"\"textname\":\"textname1\","
			"\"textdescription\":\"textdescription1\","
			"\"allowwildcardsubs\":true,"
			"\"maxPublishSize\":65536,"
			"\"publishRateLimit\":{\"messages\":50,\"perSeconds\":1,\"burst\":200},"
			"\"acls\":["
			"{\"acltype\":\"subscribeLiteral\",\"topic\":\"topic1\",\"allow\":true,\"priority\":1}"
			"]}}}]}";
	expect_request_response(&mosq, request, response);

	const char *outputs[] = {
		"Role name:",
		"  rolename1\n",
		"Text name:",
		"  textname1\n",
		"Text description:",
		"  textdescription1\n",
		"Allow wildcard subscriptions:",
		"  true\n",
		"Maximum publish payload:",
		"  65536 bytes\n",
		"Publish rate limit:",
		"  50 messages per 1 seconds, burst 200\n",
		"ACLs:",
		"  subscribeLiteral     allow topic1 (priority 1)\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, SetClientPasswordCliMatching)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("setClientPassword username1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	EXPECT_CALL(ctrl_shell_mock_, ctrl_shell_fgets(t::_, t::_, t::_))
		.WillOnce(t::Invoke([](char *s, int size, FILE *){
		snprintf(s, (size_t)size, "password1");
		return s;
	}))
		.WillOnce(t::Invoke([](char *s, int size, FILE *){
		snprintf(s, (size_t)size, "password1");
		return s;
	}));

	expect_request_response_success(&mosq,
			"{\"commands\":[{\"command\":\"setClientPassword\",\"username\":\"username1\",\"password\":\"password1\"}]}",
			"setClientPassword");

	const char *outputs[] = {
		"password:",
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, SetClientPasswordCliNotMatching)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("setClientPassword username1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	EXPECT_CALL(ctrl_shell_mock_, ctrl_shell_fgets(t::_, t::_, t::_))
		.WillOnce(t::Invoke([](char *s, int size, FILE *){
		snprintf(s, (size_t)size, "password1");
		return s;
	}))
		.WillOnce(t::Invoke([](char *s, int size, FILE *){
		snprintf(s, (size_t)size, "password2");
		return s;
	}));

	const char *outputs[] = {
		"password:",
		"Passwords do not match.\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}

TEST_F(CtrlShellDynsecTest, SetClientPasswordCliNoPassword)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("setClientPassword username1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	EXPECT_CALL(ctrl_shell_mock_, ctrl_shell_fgets(t::_, t::_, t::_))
		.WillOnce(t::Invoke([](char *, int, FILE *){
		return nullptr;
	}));

	const char *outputs[] = {
		"password:",
		"No password.\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}

TEST_F(CtrlShellDynsecTest, SetClientPasswordCliNoUsername)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("setClientPassword")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char *outputs[] = {
		"setClientPassword <username> [password]\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, AddRoleACLPublishClientReceive)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("addRoleACL rolename1 publishClientReceive allow topic1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"addRoleACL\","
			"\"rolename\":\"rolename1\","
			"\"acltype\":\"publishClientReceive\","
			"\"priority\":-1,"
			"\"topic\":\"topic1\","
			"\"allow\":true"
			"}]}";
	expect_request_response_success(&mosq, request, "addRoleACL");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, AddRoleACLPublishClientSend)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("addRoleACL rolename1 publishClientSend allow topic1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"addRoleACL\","
			"\"rolename\":\"rolename1\","
			"\"acltype\":\"publishClientSend\","
			"\"priority\":-1,"
			"\"topic\":\"topic1\","
			"\"allow\":true"
			"}]}";
	expect_request_response_success(&mosq, request, "addRoleACL");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, AddRoleACLPublishClientSendWithPriority)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("addRoleACL rolename1 publishClientSend allow 42 topic1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"addRoleACL\","
			"\"rolename\":\"rolename1\","
			"\"acltype\":\"publishClientSend\","
			"\"priority\":42,"
			"\"topic\":\"topic1\","
			"\"allow\":true"
			"}]}";
	expect_request_response_success(&mosq, request, "addRoleACL");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, AddRoleACLSubscribeLiteral)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("addRoleACL rolename1 subscribeLiteral allow topic1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"addRoleACL\","
			"\"rolename\":\"rolename1\","
			"\"acltype\":\"subscribeLiteral\","
			"\"priority\":-1,"
			"\"topic\":\"topic1\","
			"\"allow\":true"
			"}]}";
	expect_request_response_success(&mosq, request, "addRoleACL");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, AddRoleACLSubscribePattern)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("addRoleACL rolename1 subscribePattern allow topic1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"addRoleACL\","
			"\"rolename\":\"rolename1\","
			"\"acltype\":\"subscribePattern\","
			"\"priority\":-1,"
			"\"topic\":\"topic1\","
			"\"allow\":true"
			"}]}";
	expect_request_response_success(&mosq, request, "addRoleACL");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}




TEST_F(CtrlShellDynsecTest, AddRoleACLUnsubscribeLiteral)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("addRoleACL rolename1 unsubscribeLiteral allow topic1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"addRoleACL\","
			"\"rolename\":\"rolename1\","
			"\"acltype\":\"unsubscribeLiteral\","
			"\"priority\":-1,"
			"\"topic\":\"topic1\","
			"\"allow\":true"
			"}]}";
	expect_request_response_success(&mosq, request, "addRoleACL");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, AddRoleACLUnsubscribePattern)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("addRoleACL rolename1 unsubscribePattern deny topic1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"addRoleACL\","
			"\"rolename\":\"rolename1\","
			"\"acltype\":\"unsubscribePattern\","
			"\"priority\":-1,"
			"\"topic\":\"topic1\","
			"\"allow\":false"
			"}]}";
	expect_request_response_success(&mosq, request, "addRoleACL");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, AddRoleACLBadAllow)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("addRoleACL rolename1 unsubscribePattern bad topic1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char *outputs[] = {
		"Invalid allow/deny 'bad'\n",
		"addRoleACL rolename acltype allow|deny [priority] topic\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, AddRoleACLBadACLType)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("addRoleACL rolename1 bad allow topic1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char *outputs[] = {
		"Invalid acltype 'bad'\n",
		"addRoleACL rolename acltype allow|deny [priority] topic\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, AddRoleACLNoTopic)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("addRoleACL rolename1 subscribeLiteral allow")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char *outputs[] = {
		"addRoleACL rolename acltype allow|deny [priority] topic\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, RemoveRoleACLPublishClientReceive)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("removeRoleACL rolename1 publishClientReceive topic1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"removeRoleACL\","
			"\"rolename\":\"rolename1\","
			"\"acltype\":\"publishClientReceive\","
			"\"topic\":\"topic1\""
			"}]}";
	expect_request_response_success(&mosq, request, "removeRoleACL");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, RemoveRoleACLPublishClientSend)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("removeRoleACL rolename1 publishClientSend topic1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"removeRoleACL\","
			"\"rolename\":\"rolename1\","
			"\"acltype\":\"publishClientSend\","
			"\"topic\":\"topic1\""
			"}]}";
	expect_request_response_success(&mosq, request, "removeRoleACL");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, RemoveRoleACLUnsubscribeLiteral)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("removeRoleACL rolename1 unsubscribeLiteral topic1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"removeRoleACL\","
			"\"rolename\":\"rolename1\","
			"\"acltype\":\"unsubscribeLiteral\","
			"\"topic\":\"topic1\""
			"}]}";
	expect_request_response_success(&mosq, request, "removeRoleACL");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, RemoveRoleACLUnsubscribePattern)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("removeRoleACL rolename1 unsubscribePattern topic1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"removeRoleACL\","
			"\"rolename\":\"rolename1\","
			"\"acltype\":\"unsubscribePattern\","
			"\"topic\":\"topic1\""
			"}]}";
	expect_request_response_success(&mosq, request, "removeRoleACL");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, RemoveRoleACLSubscribeLiteral)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("removeRoleACL rolename1 subscribeLiteral topic1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"removeRoleACL\","
			"\"rolename\":\"rolename1\","
			"\"acltype\":\"subscribeLiteral\","
			"\"topic\":\"topic1\""
			"}]}";
	expect_request_response_success(&mosq, request, "removeRoleACL");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, RemoveRoleACLSubscribePattern)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("removeRoleACL rolename1 subscribePattern topic1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"removeRoleACL\","
			"\"rolename\":\"rolename1\","
			"\"acltype\":\"subscribePattern\","
			"\"topic\":\"topic1\""
			"}]}";
	expect_request_response_success(&mosq, request, "removeRoleACL");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, RemoveRoleACLBadACLType)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("removeRoleACL rolename1 bad topic1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char *outputs[] = {
		"Invalid acltype 'bad'\n",
		"removeRoleACL rolename acltype topic\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, RemoveRoleACLNoTopic)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("removeRoleACL rolename1 subscribeLiteral ")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char *outputs[] = {
		"removeRoleACL rolename acltype topic\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}

TEST_F(CtrlShellDynsecTest, CreateGroup)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	expect_request_response_empty(&mosq, "listClients");
	expect_request_response_empty(&mosq, "listRoles");

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listGroups\"}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_empty_response("listGroups");
		return 0;
	}))
		.WillOnce(t::Invoke([this](){
		append_empty_response("listGroups");
		return 0;
	}));

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("createGroup group1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);

	const char request[] = "{\"commands\":[{\"command\":\"createGroup\",\"groupname\":\"group1\"}]}";
	expect_request_response_success(&mosq, request, "createGroup");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}

TEST_F(CtrlShellDynsecTest, CreateRole)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	expect_request_response_empty(&mosq, "listClients");
	expect_request_response_empty(&mosq, "listGroups");

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listRoles\"}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_empty_response("listRoles");
		return 0;
	}))
		.WillOnce(t::Invoke([this](){
		append_empty_response("listRoles");
		return 0;
	}));

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("createRole role1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);

	const char request[] = "{\"commands\":[{\"command\":\"createRole\",\"rolename\":\"role1\"}]}";
	expect_request_response_success(&mosq, request, "createRole");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}

TEST_F(CtrlShellDynsecTest, DeleteClient)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	expect_request_response_empty(&mosq, "listGroups");
	expect_request_response_empty(&mosq, "listRoles");

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listClients\"}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_empty_response("listClients");
		return 0;
	}))
		.WillOnce(t::Invoke([this](){
		append_empty_response("listClients");
		return 0;
	}));

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("deleteClient user1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);

	const char request[] = "{\"commands\":[{\"command\":\"deleteClient\",\"username\":\"user1\"}]}";
	expect_request_response_success(&mosq, request, "deleteClient");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, DeleteGroup)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	expect_request_response_empty(&mosq, "listClients");
	expect_request_response_empty(&mosq, "listRoles");

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listGroups\"}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_empty_response("listGroups");
		return 0;
	}))
		.WillOnce(t::Invoke([this](){
		append_empty_response("listGroups");
		return 0;
	}));

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("deleteGroup group1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);

	const char request[] = "{\"commands\":[{\"command\":\"deleteGroup\",\"groupname\":\"group1\"}]}";
	expect_request_response_success(&mosq, request, "deleteGroup");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}

TEST_F(CtrlShellDynsecTest, DeleteRole)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	expect_request_response_empty(&mosq, "listClients");
	expect_request_response_empty(&mosq, "listGroups");

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listRoles\"}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_empty_response("listRoles");
		return 0;
	}))
		.WillOnce(t::Invoke([this](){
		append_empty_response("listRoles");
		return 0;
	}));

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("deleteRole role1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);

	const char request[] = "{\"commands\":[{\"command\":\"deleteRole\",\"rolename\":\"role1\"}]}";
	expect_request_response_success(&mosq, request, "deleteRole");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ModifyClientTextName)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("modifyClient user1 textName new name")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"modifyClient\","
			"\"username\":\"user1\","
			"\"textName\":\"new name\""
			"}]}";
	expect_request_response_success(&mosq, request, "modifyClient");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ModifyClientTextDescription)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("modifyClient user1 textDescription new description")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"modifyClient\","
			"\"username\":\"user1\","
			"\"textDescription\":\"new description\""
			"}]}";
	expect_request_response_success(&mosq, request, "modifyClient");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ModifyGroupTextName)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("modifyGroup group1 textName new name")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"modifyGroup\","
			"\"groupname\":\"group1\","
			"\"textName\":\"new name\""
			"}]}";
	expect_request_response_success(&mosq, request, "modifyGroup");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ModifyGroupTextDescription)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("modifyGroup group1 textDescription new description")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"modifyGroup\","
			"\"groupname\":\"group1\","
			"\"textDescription\":\"new description\""
			"}]}";
	expect_request_response_success(&mosq, request, "modifyGroup");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ModifyRolePublishLimits)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);
	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("modifyRole role1 maxPublishSize 65536")))
		.WillOnce(t::Return(strdup("modifyRole role1 publishRateLimit {\"messages\":50, \"perSeconds\":1, \"burst\":200}")))
		.WillOnce(t::Return(strdup("modifyRole role1 publishRateLimit null")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);
	expect_request_response_success(&mosq,
		"{\"commands\":[{\"command\":\"modifyRole\",\"rolename\":\"role1\",\"maxPublishSize\":65536}]}", "modifyRole");
	expect_request_response_success(&mosq,
		"{\"commands\":[{\"command\":\"modifyRole\",\"rolename\":\"role1\",\"publishRateLimit\":{\"messages\":50,\"perSeconds\":1,\"burst\":200}}]}", "modifyRole");
	expect_request_response_success(&mosq,
		"{\"commands\":[{\"command\":\"modifyRole\",\"rolename\":\"role1\",\"publishRateLimit\":null}]}", "modifyRole");
	const char *outputs[] = {"OK\n", "\n"};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));
	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ModifyRolePublishLimitsInvalid)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);
	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("modifyRole role1 maxPublishSize 123 garbage")))
		.WillOnce(t::Return(strdup("modifyRole role1 publishRateLimit true")))
		.WillOnce(t::Return(strdup("exit")));
	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);
	const char *outputs[] = {
		"Invalid publish limit '123 garbage'\n",
		"Invalid publish limit 'true'\n", "\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));
	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ModifyRoleTextName)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("modifyRole role1 textName new name")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"modifyRole\","
			"\"rolename\":\"role1\","
			"\"textName\":\"new name\""
			"}]}";
	expect_request_response_success(&mosq, request, "modifyRole");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ModifyRoleTextDescription)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("modifyRole role1 textDescription new description")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"modifyRole\","
			"\"rolename\":\"role1\","
			"\"textDescription\":\"new description\""
			"}]}";
	expect_request_response_success(&mosq, request, "modifyRole");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ModifyRoleWildcardSubs)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("modifyRole role1 allowWildcardSubs true")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char request[] = "{\"commands\":[{"
			"\"command\":\"modifyRole\","
			"\"rolename\":\"role1\","
			"\"allowWildcardSubs\":true"
			"}]}";
	expect_request_response_success(&mosq, request, "modifyRole");

	const char *outputs[] = {
		"OK\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ModifyRoleAllowWildcardSubsBadValue)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("modifyRole role1 allowWildcardSubs bad")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char *outputs[] = {
		"modifyRole rolename <property> <value>\n",
		"Invalid value 'bad'\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ModifyRoleBadProp)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("modifyRole role1 badprop new description")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char *outputs[] = {
		"modifyRole rolename <property> <value>\n",
		"Unknown property 'badprop'\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ModifyRoleNoProp)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("modifyRole role1")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_single_lists(&mosq);

	const char *outputs[] = {
		"modifyRole rolename <property> <value>\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ListClients)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("listClients")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_request_response_empty(&mosq, "listGroups");
	expect_request_response_empty(&mosq, "listRoles");

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listClients\"}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_response("{\"responses\":[{\"command\":\"listClients\",\"data\":{"
		"\"clients\":[\"client1\",\"client2\"]"
		"}}]}");
		return 0;
	}))
		.WillOnce(t::Invoke([this](){
		append_response("{\"responses\":[{\"command\":\"listClients\",\"data\":{"
		"\"clients\":[\"client1\",\"client2\"]"
		"}}]}");
		return 0;
	}));


	const char *outputs[] = {
		"client1\n",
		"client2\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ListClientsWithCount)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("listClients 2")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_request_response_empty(&mosq, "listClients");
	expect_request_response_empty(&mosq, "listGroups");
	expect_request_response_empty(&mosq, "listRoles");

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listClients\",\"count\":2}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_response("{\"responses\":[{\"command\":\"listClients\",\"data\":{"
		"\"clients\":[\"client1\",\"client2\"]"
		"}}]}");
		return 0;
	}));


	const char *outputs[] = {
		"client1\n",
		"client2\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ListClientsWithCountAndOffset)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("listClients 2 3")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_request_response_empty(&mosq, "listClients");
	expect_request_response_empty(&mosq, "listGroups");
	expect_request_response_empty(&mosq, "listRoles");

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listClients\",\"count\":2,\"offset\":3}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_response("{\"responses\":[{\"command\":\"listClients\",\"data\":{"
		"\"clients\":[\"client1\",\"client2\"]"
		"}}]}");
		return 0;
	}));


	const char *outputs[] = {
		"client1\n",
		"client2\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ListGroups)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("listGroups")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_request_response_empty(&mosq, "listClients");
	expect_request_response_empty(&mosq, "listRoles");

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listGroups\"}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_response("{\"responses\":[{\"command\":\"listGroups\",\"data\":{"
		"\"groups\":[\"group1\",\"group2\"]"
		"}}]}");
		return 0;
	}))
		.WillOnce(t::Invoke([this](){
		append_response("{\"responses\":[{\"command\":\"listGroups\",\"data\":{"
		"\"groups\":[\"group1\",\"group2\"]"
		"}}]}");
		return 0;
	}));


	const char *outputs[] = {
		"group1\n",
		"group2\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ListGroupsWithCount)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("listGroups 2")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_request_response_empty(&mosq, "listClients");
	expect_request_response_empty(&mosq, "listGroups");
	expect_request_response_empty(&mosq, "listRoles");

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listGroups\",\"count\":2}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_response("{\"responses\":[{\"command\":\"listGroups\",\"data\":{"
		"\"groups\":[\"group1\",\"group2\"]"
		"}}]}");
		return 0;
	}));


	const char *outputs[] = {
		"group1\n",
		"group2\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ListGroupsWithCountAndOffset)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("listGroups 2 3")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_request_response_empty(&mosq, "listClients");
	expect_request_response_empty(&mosq, "listGroups");
	expect_request_response_empty(&mosq, "listRoles");

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listGroups\",\"count\":2,\"offset\":3}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_response("{\"responses\":[{\"command\":\"listGroups\",\"data\":{"
		"\"groups\":[\"group1\",\"group2\"]"
		"}}]}");
		return 0;
	}));


	const char *outputs[] = {
		"group1\n",
		"group2\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ListRoles)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("listRoles")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_request_response_empty(&mosq, "listClients");
	expect_request_response_empty(&mosq, "listGroups");

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listRoles\"}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_response("{\"responses\":[{\"command\":\"listRoles\",\"data\":{"
		"\"roles\":[\"role1\",\"role2\"]"
		"}}]}");
		return 0;
	}))
		.WillOnce(t::Invoke([this](){
		append_response("{\"responses\":[{\"command\":\"listRoles\",\"data\":{"
		"\"roles\":[\"role1\",\"role2\"]"
		"}}]}");
		return 0;
	}));


	const char *outputs[] = {
		"role1\n",
		"role2\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ListRolesWithCount)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("listRoles 2")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_request_response_empty(&mosq, "listClients");
	expect_request_response_empty(&mosq, "listGroups");
	expect_request_response_empty(&mosq, "listRoles");

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listRoles\",\"count\":2}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_response("{\"responses\":[{\"command\":\"listRoles\",\"data\":{"
		"\"roles\":[\"role1\",\"role2\"]"
		"}}]}");
		return 0;
	}));


	const char *outputs[] = {
		"role1\n",
		"role2\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, ListRolesWithCountAndOffset)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("listRoles 2 3")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_request_response_empty(&mosq, "listClients");
	expect_request_response_empty(&mosq, "listGroups");
	expect_request_response_empty(&mosq, "listRoles");

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"listRoles\",\"count\":2,\"offset\":3}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_response("{\"responses\":[{\"command\":\"listRoles\",\"data\":{"
		"\"roles\":[\"role1\",\"role2\"]"
		"}}]}");
		return 0;
	}));


	const char *outputs[] = {
		"role1\n",
		"role2\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}


TEST_F(CtrlShellDynsecTest, GetDetails)
{
	mosq_config config{};
	mosquitto mosq{};
	const char host[] = "localhost";
	int port = 1883;

	expect_setup(&config);
	expect_connect(&mosq, host, port);
	expect_dynsec(host, port);

	EXPECT_CALL(editline_mock_, readline(t::StrEq("mqtt://localhost:1883|dynsec> ")))
		.WillOnce(t::Return(strdup("getDetails")))
		.WillOnce(t::Return(strdup("exit")));

	expect_connect_and_messages(&mosq);
	expect_request_response_empty(&mosq, "listClients");
	expect_request_response_empty(&mosq, "listGroups");
	expect_request_response_empty(&mosq, "listRoles");

	EXPECT_CALL(libmosquitto_mock_, mosquitto_publish(t::Eq(&mosq), nullptr, t::StrEq("$CONTROL/dynamic-security/v1"), t::_,
			t::StrEq("{\"commands\":[{\"command\":\"getDetails\"}]}"), 1, false))
		.WillOnce(t::Invoke([this](){
		append_response("{\"responses\":[{\"command\":\"getDetails\",\"data\":{"
		"\"clientCount\":1,"
		"\"groupCount\":2,"
		"\"roleCount\":3,"
		"\"changeIndex\":4"
		"}}]}");
		return 0;
	}));


	const char *outputs[] = {
		"Client count:",
		"Group count:",
		"Role count:",
		"Change index:",
		"   1\n",
		"    2\n",
		"     3\n",
		"   4\n",
		"\n",
	};
	expect_outputs(outputs, sizeof(outputs)/sizeof(char *));

	ctrl_shell__main(&config);
	EXPECT_EQ(pending_payloads, nullptr);
}
