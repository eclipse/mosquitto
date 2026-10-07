/*
Copyright (c) 2023 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include <config.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <time.h>

#ifndef WIN32
#  include <netinet/in.h>
#  include <unistd.h>
#endif

#include "ctrl_shell.h"
#include "ctrl_shell_internal.h"

#define UNUSED(A) (void)(A)

#ifdef WITH_CTRL_SHELL

#define FREE(A) do{free(A); A = NULL;}while(0)

const char *ANSI_URL = NULL;
const char *ANSI_MODULE = NULL;
const char *ANSI_INPUT = NULL;
const char *ANSI_ERROR = NULL;
const char **ANSI_LABEL = NULL;
const char *ANSI_RESET = "\001\e[0m\002";
const char *ANSI_TOPIC = NULL;
const char *ANSI_POSITIVE = NULL;
const char *ANSI_NEGATIVE = NULL;

const char *ANSI_LABEL_none[] = {"", ""};

const char ANSI_URL_dark[] =     "\001\e[38;5;155m\002";
const char ANSI_MODULE_dark[] =  "\001\e[38;5;214m\002";
const char ANSI_INPUT_dark[] =   "\001\e[38;5;80m\002";
const char ANSI_ERROR_dark[] =   "\001\e[38;5;198m\002";
const char *ANSI_LABEL_dark[] =  {
	"\001\e[38;5;207m\002",
	"\001\e[38;5;219m\002",
};
const char ANSI_TOPIC_dark[] =    "\001\e[93m\002";
const char ANSI_POSITIVE_dark[] =    "\001\e[92m\002";
const char ANSI_NEGATIVE_dark[] =    "\001\e[95m\002";

const char ANSI_URL_light[] =    "\001\e[38;5;23m\002";
const char ANSI_MODULE_light[] = "\001\e[38;5;130m\002";
const char ANSI_INPUT_light[] =  "\001\e[38;5;27m\002";
const char ANSI_ERROR_light[] =  "\001\e[38;5;196m\002";
const char *ANSI_LABEL_light[] =  {
	"\001\e[38;5;165m\002",
	"\001\e[38;5;171m\002",
};
const char ANSI_TOPIC_light[] =    "\001\e[33m\002";
const char ANSI_POSITIVE_light[] =    "\001\e[32m\002";
const char ANSI_NEGATIVE_light[] =    "\001\e[35m\002";


char prompt[200];
struct ctrl_shell data;
static int generator_arg = -1;
struct completion_tree_cmd *current_cmd_match = NULL;


static void signal_winch(int signal)
{
	UNUSED(signal);
	rl_resize_terminal();
}


static void signal_term(int signal)
{
	UNUSED(signal);
	data.run = 0;
}


static void term_set_flag(bool set, unsigned int flag)
{
	struct termios ts;

	tcgetattr(0, &ts);
	if(set){
		ts.c_lflag |= (flag);
	}else{
		ts.c_lflag &= (unsigned int)(~flag);
	}
	tcsetattr(0, TCSANOW, &ts);
}


static void term_set_echo(bool echo)
{
	term_set_flag(echo, ECHO);
}


static void term_set_canon(bool canon)
{
	term_set_flag(canon, ICANON);
}


void ctrl_shell_rtrim(char *buf)
{
	size_t slen = strlen(buf);
	while(slen > 0 && isspace((unsigned char)buf[slen-1])){
		buf[slen-1] = '\0';
		slen = strlen(buf);
	}
}


bool ctrl_shell_get_password(char *buf, size_t len)
{
	ctrl_shell_printf("%spassword:%s", ANSI_INPUT, ANSI_RESET);
	term_set_echo(false);
	if(ctrl_shell_fgets(buf, (int)len, stdin) == NULL){
		term_set_echo(true);
		return false;
	}
	term_set_echo(true);
	ctrl_shell_printf("\n");

	ctrl_shell_rtrim(buf);
	return true;
}


static int response_wait(void)
{
	struct timespec timeout;
	int rc = 0;

	data.response_received = false;

	clock_gettime(CLOCK_REALTIME, &timeout);
	timeout.tv_sec += 2;
	while(data.response_received == false){
		if(pthread_cond_timedwait(&data.response_cond, &data.response_mutex, &timeout) == ETIMEDOUT){
			ctrl_shell_printf("Timed out with no response.\n");
			rc = 1;
			break;
		}
	}

	return rc;
}


int ctrl_shell_publish_blocking(cJSON *j_command)
{
	int rc = 0;

	cJSON *j_commands = cJSON_CreateObject();
	cJSON *j_array = cJSON_AddArrayToObject(j_commands, "commands");
	cJSON_AddItemToArray(j_array, j_command);

	char *payload = cJSON_PrintUnformatted(j_commands);
	cJSON_Delete(j_commands);

	pthread_mutex_lock(&data.response_mutex);

	mosquitto_publish(data.mosq, NULL, data.request_topic, (int)strlen(payload), payload, 1, false);
	FREE(payload);

	/* Check for publish callback */
	rc = response_wait();
	if(rc){
		pthread_mutex_unlock(&data.response_mutex);
		return rc;
	}

	if(data.publish_rc >= 128){
		pthread_mutex_unlock(&data.response_mutex);
		return 1;
	}

	/* Check for message callback */
	rc = response_wait();
	pthread_mutex_unlock(&data.response_mutex);

	return rc;
}


void ctrl_shell__connect_blocking(const char *hostname, int port)
{
	pthread_mutex_lock(&data.response_mutex);

	int rc = mosquitto_connect(data.mosq, hostname, port, 60);
	rc = mosquitto_loop_start(data.mosq);

	/* FIXME - do something with the error */
	UNUSED(rc);

	response_wait();
	pthread_mutex_unlock(&data.response_mutex);
}


void ctrl_shell_line_callback_set(void (*callback)(char *line))
{
	data.line_callback = callback;
}


int ctrl_shell_command_generic_arg0(const char *command)
{
	cJSON *j_command = cJSON_CreateObject();
	cJSON_AddStringToObject(j_command, "command", command);

	return ctrl_shell_publish_blocking(j_command);
}


int ctrl_shell_command_generic_arg1(const char *command, const char *itemlabel, char **saveptr)
{
	const char *item;

	item = strtok_r(NULL, " ", saveptr);
	if(!item){
		ctrl_shell_printf("%s %s\n", command, itemlabel);
		return MOSQ_ERR_INVAL;
	}

	cJSON *j_command = cJSON_CreateObject();
	cJSON_AddStringToObject(j_command, "command", command);
	cJSON_AddStringToObject(j_command, itemlabel, item);

	return ctrl_shell_publish_blocking(j_command);
}


int ctrl_shell_command_generic_int_arg1(const char *command, const char *itemlabel, char **saveptr)
{
	const char *item;

	item = strtok_r(NULL, " ", saveptr);
	if(!item){
		ctrl_shell_printf("%s %s\n", command, itemlabel);
		return MOSQ_ERR_INVAL;
	}
	int intval = atoi(item);

	cJSON *j_command = cJSON_CreateObject();
	cJSON_AddStringToObject(j_command, "command", command);
	cJSON_AddNumberToObject(j_command, itemlabel, intval);

	return ctrl_shell_publish_blocking(j_command);
}


int ctrl_shell_command_generic_arg2(const char *command, const char *itemlabel1, const char *itemlabel2, char **saveptr)
{
	const char *item1, *item2;

	item1 = strtok_r(NULL, " ", saveptr);
	item2 = strtok_r(NULL, " ", saveptr);
	if(!item1 || !item2){
		ctrl_shell_printf("%s %s %s\n", command, itemlabel1, itemlabel2);
		return MOSQ_ERR_INVAL;
	}

	cJSON *j_command = cJSON_CreateObject();
	cJSON_AddStringToObject(j_command, "command", command);
	cJSON_AddStringToObject(j_command, itemlabel1, item1);
	cJSON_AddStringToObject(j_command, itemlabel2, item2);

	return ctrl_shell_publish_blocking(j_command);
}


static int ctrl_shell__subscribe_blocking(const char *topic, void (*module_on_subscribe)(void))
{
	int rc = 0;

	for(int i=0; i<data.subscription_list_count; i++){
		if(!strcmp(data.subscription_list[i], topic)){
			return 0;
		}
	}

	char **new_subscriptions = realloc(data.subscription_list, (size_t)(data.subscription_list_count+1)*sizeof(char *));
	if(new_subscriptions){
		data.subscription_list = new_subscriptions;
		data.subscription_list_count++;
		data.subscription_list[data.subscription_list_count-1] = strdup(topic);
	}

	pthread_mutex_lock(&data.response_mutex);

	mosquitto_subscribe(data.mosq, NULL, topic, 1);

	response_wait();
	pthread_mutex_unlock(&data.response_mutex);

	if(data.subscribe_rc >= 128){
		rc = 1;
	}else{
		if(module_on_subscribe){
			module_on_subscribe();
		}
	}

	return rc;
}


bool ctrl_shell_callback_final(char *line)
{
	if(!line || !strcasecmp(line, "exit")){
		data.run = 0;
	}else if(!strcasecmp(line, "disconnect")){
		if(data.mosq){
			ctrl_shell__disconnect();
		}else{
			return false;
		}
	}else if(!strcasecmp(line, "return")){
		if(data.mod_cleanup){
			data.mod_cleanup();
		}
		ctrl_shell__post_connect_init();
	}else{
		return false;
	}
	return true;
}


void ctrl_shell_print_help_final(const char *command, const char *modul)
{
	if(!strcasecmp(command, "disconnect")){
		ctrl_shell_print_help_command("disconnect");
		ctrl_shell_printf("\nDisconnect from the broker\n");
	}else if(!strcasecmp(command, "exit")){
		ctrl_shell_print_help_command("exit");
		ctrl_shell_printf("\nQuit the program\n");
	}else if(!strcasecmp(command, "help")){
		ctrl_shell_print_help_command("help <command>");
		ctrl_shell_printf("\nFind help on a command using 'help <command>'\n");
		ctrl_shell_printf("Press tab multiple times to find currently available commands.\n");
	}else if(modul && !strcasecmp(command, "return")){
		ctrl_shell_print_help_command("return");
		ctrl_shell_printf("\nLeave %s mode.\n", modul);
	}else{
		ctrl_shell_printf("Unknown command '%s'\n", command);
	}
}


static void calc_generator_arg(int start)
{
	char *text_heap;
	char *text_arg, *saveptr = NULL;
	int ga = 0;

	if(start == 0){
		generator_arg = -1;
		return;
	}

	text_heap = strdup(rl_line_buffer);
	if(!text_heap){
		return;
	}
	text_heap[start] = '\0';
	text_arg = strtok_r(text_heap, " ", &saveptr);
	while(text_arg){
		ga++;
		text_arg = strtok_r(NULL, " ", &saveptr);
	}
	FREE(text_heap);

	generator_arg = ga-1;
}


char *completion_generator(const char *text, int state)
{
	static size_t len;
	static struct completion_tree_cmd *cmd, *cmd_prev;
	static struct completion_tree_arg *arg;

	if(!data.commands){
		return NULL;
	}
	if(!state){
		len = strlen(text);
		if(generator_arg < 0){
			cmd = data.commands->commands;
		}else if(current_cmd_match && generator_arg < current_cmd_match->arg_list_count){
			arg = current_cmd_match->arg_lists[generator_arg]->args;
		}else{
			return NULL;
		}
	}

	if(generator_arg < 0){
		while(cmd){
			char *name = cmd->name;
			cmd_prev = cmd;
			cmd = cmd->next;

			if(strncasecmp(name, text, len) == 0){
				current_cmd_match = cmd_prev;
				return strdup(name);
			}
		}
	}else{
		while(arg){
			char *name = arg->name;
			arg = arg->next;

			if(strncasecmp(name, text, len) == 0){
				return strdup(name);
			}
		}
	}

	return NULL;
}


void ctrl_shell_completion_commands_set(struct completion_tree_root *new_commands)
{
	data.commands = new_commands;
}


char **completion_matcher(const char *text, int start, int end)
{
	char **matches;

	UNUSED(end);

	rl_attempted_completion_over = 1;
	calc_generator_arg(start);
	matches = rl_completion_matches(text, completion_generator);
	return matches;
}


int my_get_address(int sock, char *buf, size_t len, uint16_t *remote_port)
{
	struct sockaddr_storage addr;
	socklen_t addrlen;

	if(sock < 0){
		memset(buf, 0, len);
		*remote_port = 0;
		return 1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_storage));
	addrlen = sizeof(addr);
	if(!getpeername(sock, (struct sockaddr *)&addr, &addrlen)){
		if(addr.ss_family == AF_INET){
			if(remote_port){
				*remote_port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
			}
			if(inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr.s_addr, buf, (socklen_t)len)){
				return 0;
			}
		}else if(addr.ss_family == AF_INET6){
			if(remote_port){
				*remote_port = ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
			}
			if(inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr.s6_addr, buf, (socklen_t)len)){
				return 0;
			}
		}
	}
	return 1;
}


static void on_connect_reconnect(struct mosquitto *mosq, void *userdata, int rc)
{
	UNUSED(userdata);
	UNUSED(rc);

	for(int i=0; i<data.subscription_list_count; i++){
		if(data.subscription_list[i]){
			mosquitto_subscribe(mosq, NULL, data.subscription_list[i], 1);
		}
	}
}


void ctrl_shell__on_connect(struct mosquitto *mosq, void *userdata, int rc)
{
	UNUSED(userdata);

	mosquitto_connect_callback_set(mosq, on_connect_reconnect);

	data.connect_rc = rc;

	data.response_received = true;
	pthread_mutex_unlock(&data.response_mutex);
	pthread_cond_signal(&data.response_cond);
}


void ctrl_shell__on_message(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *msg)
{
	UNUSED(mosq);
	UNUSED(userdata);

	cJSON *j_tree = cJSON_Parse((char *)msg->payload);
	cJSON *j_endpoint_error = cJSON_GetObjectItem(j_tree, "error");
	if(j_endpoint_error && !strcmp(j_endpoint_error->valuestring, "endpoint not available")){
		ctrl_shell_printf("%s$CONTROL endpoint for this module not available.%s\n", ANSI_ERROR, ANSI_RESET);
	}else{
		cJSON *j_responses = cJSON_GetObjectItem(j_tree, "responses");
		cJSON *j_command_obj = cJSON_GetArrayItem(j_responses, 0);
		cJSON *j_command = cJSON_GetObjectItem(j_command_obj, "command");
		cJSON *j_error = cJSON_GetObjectItem(j_command_obj, "error");
		cJSON *j_data = cJSON_GetObjectItem(j_command_obj, "data");
		if(j_error){
			ctrl_shell_printf("%s%s%s\n", ANSI_ERROR, j_error->valuestring, ANSI_RESET);
		}else if(j_data && data.response_callback){
			data.response_callback(j_command->valuestring, j_data, msg->payload);
		}else if(j_command){
			ctrl_shell_printf("OK\n");
		}else{
			ctrl_shell_printf("Invalid response from broker.\n");
		}
	}

	cJSON_Delete(j_tree);

	data.response_received = true;
	pthread_mutex_unlock(&data.response_mutex);
	pthread_cond_signal(&data.response_cond);
}


void ctrl_shell__on_publish(struct mosquitto *mosq, void *userdata, int mid, int reason_code, const mosquitto_property *props)
{
	UNUSED(mosq);
	UNUSED(userdata);
	UNUSED(mid);
	UNUSED(props);

	if(reason_code >= 128){
		ctrl_shell_printf("Publish failed, check you have permission to access this module.\n");
		data.publish_rc = reason_code;
	}

	data.response_received = true;
	pthread_mutex_unlock(&data.response_mutex);
	pthread_cond_signal(&data.response_cond);
}


void ctrl_shell__on_subscribe(struct mosquitto *mosq, void *userdata, int mid, int qos_count, const int *granted_qos)
{
	UNUSED(mosq);
	UNUSED(userdata);
	UNUSED(mid);

	if(qos_count == 1 && granted_qos[0] >= 128){
		ctrl_shell_printf("Subscribe failed, check you have permission to access this module.\n");
		data.subscribe_rc = granted_qos[0];
	}

	data.response_received = true;
	pthread_mutex_unlock(&data.response_mutex);
	pthread_cond_signal(&data.response_cond);
}


void ctrl_shell__load_module(void (*mod_init)(struct ctrl_shell__module *mod))
{
	struct ctrl_shell__module mod;
	memset(&mod, 0, sizeof(mod));
	mod_init(&mod);

	data.request_topic = mod.request_topic;
	data.response_callback = mod.response_callback;
	data.mod_cleanup = mod.cleanup;

	ctrl_shell_completion_commands_set(mod.completion_commands);
	ctrl_shell_line_callback_set(mod.line_callback);
	ctrl_shell__subscribe_blocking(mod.response_topic, mod.on_subscribe);
}


void set_no_colour(void)
{
	ANSI_URL = "";
	ANSI_MODULE = "";
	ANSI_INPUT = "";
	ANSI_ERROR = "";
	ANSI_LABEL = ANSI_LABEL_none;
	ANSI_RESET = "";
	ANSI_TOPIC = "";
	ANSI_POSITIVE = "";
	ANSI_NEGATIVE = "";
}


static void set_bg_light(void)
{
	ANSI_URL = ANSI_URL_light;
	ANSI_MODULE = ANSI_MODULE_light;
	ANSI_INPUT = ANSI_INPUT_light;
	ANSI_ERROR = ANSI_ERROR_light;
	ANSI_LABEL = ANSI_LABEL_light;
	ANSI_TOPIC = ANSI_TOPIC_light;
	ANSI_POSITIVE = ANSI_POSITIVE_light;
	ANSI_NEGATIVE = ANSI_NEGATIVE_light;
}


static void set_bg_dark(void)
{
	ANSI_URL = ANSI_URL_dark;
	ANSI_MODULE = ANSI_MODULE_dark;
	ANSI_INPUT = ANSI_INPUT_dark;
	ANSI_ERROR = ANSI_ERROR_dark;
	ANSI_LABEL = ANSI_LABEL_dark;
	ANSI_TOPIC = ANSI_TOPIC_dark;
	ANSI_POSITIVE = ANSI_POSITIVE_dark;
	ANSI_NEGATIVE = ANSI_NEGATIVE_dark;
}


static int get_bg(void)
{
	int opt;

	/* Set non-blocking */
	opt = fcntl(STDIN_FILENO, F_GETFL, 0);
	if(fcntl(STDIN_FILENO, F_SETFL, opt | O_NONBLOCK) < 0){
		fprintf(stderr, "Error: Unable to set terminal flags required.");
		return 1;
	}

	set_bg_dark();

	term_set_echo(false);
	term_set_canon(false);
	ctrl_shell_printf("\e]10;?\a\e]11;?\a");
	fflush(stdout);

	char buf[50] = {0};
	ssize_t rl;
	usleep(100000);
	do{
		rl = read(STDIN_FILENO, buf, sizeof(buf));
	}while(rl == 0);
	if(fcntl(STDIN_FILENO, F_SETFL, opt) < 0){
		fprintf(stderr, "Error: Unable to reset terminal flags.");
		return 1;
	}
	term_set_echo(true);
	term_set_canon(true);

	for(int i=0; i<rl; i++){
		if(buf[i] == 7 || buf[i] == 27 || buf[i] == ']'){
			buf[i] = ' ';
		}
	}
	int r_fg = 0, g_fg = 0, b_fg = 0;
	int r_bg = 0, g_bg = 0, b_bg = 0;
	int s = sscanf(buf+2, "10;rgb:%x/%x/%x   11;rgb:%x/%x/%x", &r_fg, &g_fg, &b_fg, &r_bg, &g_bg, &b_bg);
	if(s != 6){
		return 1;
	}
	int fg, bg;

	fg = r_fg + b_fg + g_fg;
	bg = r_bg + b_bg + g_bg;

	if(fg > bg){
		set_bg_dark();
	}else{
		set_bg_light();
	}
	return 0;
}


void ctrl_shell__cleanup(void)
{
	FREE(data.hostname);
	for(int i=0; i<data.subscription_list_count; i++){
		FREE(data.subscription_list[i]);
	}
	FREE(data.subscription_list);

	ctrl_shell__pre_connect_cleanup();
	ctrl_shell__post_connect_cleanup();
	if(data.mod_cleanup){
		data.mod_cleanup();
	}
	FREE(data.username);
	FREE(data.password);
	FREE(data.clientid);
	FREE(data.tls_cafile);
	FREE(data.tls_capath);
	FREE(data.tls_certfile);
	FREE(data.tls_keyfile);
}


void ctrl_shell__main(struct mosq_config *config)
{
	memset(&data, 0, sizeof(data));
	data.url_scheme = "mqtt";
	data.run = 1;
	data.port = PORT_UNDEFINED;
	data.connect_rc = -1;

	if(config && config->no_colour){
		set_no_colour();
	}else{
		if(get_bg()){
			return;
		}
	}

	if(config){
		if(config->host){
			data.hostname = strdup(config->host);
		}
		if(config->port != PORT_UNDEFINED){
			data.port = config->port;
		}
		if(config->username){
			data.username = strdup(config->username);
		}
		if(config->password){
			data.password = strdup(config->password);
		}
		if(config->id){
			data.clientid = strdup(config->id);
		}
		if(config->cafile){
			data.tls_cafile = strdup(config->cafile);
		}
		if(config->capath){
			data.tls_capath = strdup(config->capath);
		}
		if(config->certfile){
			data.tls_certfile = strdup(config->certfile);
		}
		if(config->keyfile){
			data.tls_keyfile = strdup(config->keyfile);
		}

	}

	pthread_mutex_init(&data.response_mutex, NULL);
	pthread_cond_init(&data.response_cond, NULL);

	rl_readline_name = "mosquitto_ctrl";
	rl_completion_entry_function = completion_generator;
	rl_attempted_completion_function = completion_matcher;
	rl_bind_key('\t', rl_complete);

	signal(SIGWINCH, signal_winch);
	signal(SIGTERM, signal_term);
	signal(SIGINT, signal_term);

	ctrl_shell_printf("mosquitto_ctrl shell v" VERSION "\n");

	if(data.hostname){
		if(ctrl_shell__connect()){
			ctrl_shell__cleanup();
			return;
		}
	}else{
		ctrl_shell__pre_connect_init();
	}

	while(data.run){
		current_cmd_match = NULL;
		char *line = readline(prompt);
		if(data.line_callback){
			data.line_callback(line);
		}
	}
	clear_history();

	ctrl_shell_printf("\n");

	ctrl_shell__cleanup();
}


static void print_label(unsigned int level, const char *label)
{
	char *str = calloc(1, level*2 + strlen(label) + 30);

	for(unsigned int i=0; i<level; i++){
		sprintf(&str[strlen(str)], "  ");
	}
	if(level < 2){
		sprintf(&str[strlen(str)], "%s", ANSI_LABEL[level]);
	}else{
		sprintf(&str[strlen(str)], "%s", ANSI_LABEL[1]);
	}
	sprintf(&str[strlen(str)], "%s%s", label, ANSI_RESET);

	ctrl_shell_printf("%s", str);
	free(str);
}


void ctrl_shell_print_label(unsigned int level, const char *label)
{
	print_label(level, label);
	ctrl_shell_printf("\n");
}


void ctrl_shell_print_label_value(unsigned int level, const char *label, int align, const char *fmt, ...)
{
	va_list va;
	int levels = align-((int)strlen(label)+2*(int)level)+2;
	char *str = calloc(1, (size_t)levels + 200);

	print_label(level, label);

	for(int i=0; i<align-((int)strlen(label)+2*(int)level)+2; i++){
		sprintf(&str[strlen(str)], " ");
	}

	va_start(va, fmt);
	vsprintf(&str[strlen(str)], fmt, va);
	va_end(va);

	ctrl_shell_printf("%s", str);
	free(str);
}


void ctrl_shell_print_value(unsigned int level, const char *fmt, ...)
{
	va_list va;
	char *str = calloc(1, level*2 + 200);

	for(unsigned int i=0; i<level; i++){
		sprintf(&str[strlen(str)], "  ");
	}
	va_start(va, fmt);
	vsprintf(&str[strlen(str)], fmt, va);
	va_end(va);
	ctrl_shell_printf("%s", str);
	free(str);
}


void ctrl_shell_print_help_command(const char *cmd)
{
	ctrl_shell_printf("%s%s%s\n", ANSI_INPUT, cmd, ANSI_RESET);
}


void ctrl_shell_print_help_desc(const char *desc)
{
	ctrl_shell_printf("  %s\n", desc);
}
#endif
