#ifndef DYNAMIC_SECURITY_H
#define DYNAMIC_SECURITY_H
/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR EDL-1.0

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include <cjson/cJSON.h>
#include <uthash.h>
#include "mosquitto.h"
#include "password_mosq.h"

/* ################################################################
 * #
 * # ACL types
 * #
 * ################################################################ */

#define ACL_TYPE_PUB_C_RECV "publishClientReceive"
#define ACL_TYPE_PUB_C_SEND "publishClientSend"
#define ACL_TYPE_SUB_GENERIC "subscribe"
#define ACL_TYPE_SUB_LITERAL "subscribeLiteral"
#define ACL_TYPE_SUB_PATTERN "subscribePattern"
#define ACL_TYPE_UNSUB_GENERIC "unsubscribe"
#define ACL_TYPE_UNSUB_LITERAL "unsubscribeLiteral"
#define ACL_TYPE_UNSUB_PATTERN "unsubscribePattern"

/* ################################################################
 * #
 * # Error codes
 * #
 * ################################################################ */

#define ERR_USER_NOT_FOUND 10000
#define ERR_GROUP_NOT_FOUND 10001
#define ERR_LIST_NOT_FOUND 10002

/* ################################################################
 * #
 * # Datatypes
 * #
 * ################################################################ */

struct dynsec__clientlist{
	UT_hash_handle hh;
	struct dynsec__client *client;
	int priority;
};

struct dynsec__grouplist{
	UT_hash_handle hh;
	struct dynsec__group *group;
	int priority;
};

struct dynsec__rolelist{
	UT_hash_handle hh;
	char *rolename;
	struct dynsec__role *role;
	int priority;
};

struct dynsec__client{
	UT_hash_handle hh;
	struct mosquitto_pw pw;
	struct dynsec__rolelist *rolelist;
	struct dynsec__grouplist *grouplist;
	char *username;
	char *clientid;
	char *text_name;
	char *text_description;
	bool disabled;
};

struct dynsec__group{
	UT_hash_handle hh;
	struct dynsec__rolelist *rolelist;
	struct dynsec__clientlist *clientlist;
	char *groupname;
	char *text_name;
	char *text_description;
};


struct dynsec__acl{
	UT_hash_handle hh;
	char *topic;
	int priority;
	bool allow;
};

struct dynsec__acls{
	struct dynsec__acl *publish_c_send;
	struct dynsec__acl *publish_c_recv;
	struct dynsec__acl *subscribe_literal;
	struct dynsec__acl *subscribe_pattern;
	struct dynsec__acl *unsubscribe_literal;
	struct dynsec__acl *unsubscribe_pattern;
};

struct dynsec__role{
	UT_hash_handle hh;
	struct dynsec__acls acls;
	struct dynsec__clientlist *clientlist;
	struct dynsec__grouplist *grouplist;
	char *rolename;
	char *text_name;
	char *text_description;
};

struct dynsec__acl_default_access{
	bool publish_c_send;
	bool publish_c_recv;
	bool subscribe;
	bool unsubscribe;
};

extern struct dynsec__group *dynsec_anonymous_group;
extern struct dynsec__acl_default_access default_access;

/* ################################################################
 * #
 * # Plugin Functions
 * #
 * ################################################################ */

void dynsec__config_save(void);
int dynsec__handle_control(cJSON *j_responses, struct mosquitto *context, cJSON *commands);
void dynsec__command_reply(cJSON *j_responses, struct mosquitto *context, const char *command, const char *error, const char *correlation_data);


/* ################################################################
 * #
 * # ACL Functions
 * #
 * ################################################################ */

int dynsec__acl_check_callback(int event, void *event_data, void *userdata);
bool sub_acl_check(const char *acl, const char *sub);


/* ################################################################
 * #
 * # Auth Functions
 * #
 * ################################################################ */

int dynsec_auth__base64_encode(unsigned char *in, int in_len, char **encoded);
int dynsec_auth__base64_decode(char *in, unsigned char **decoded, int *decoded_len);
int dynsec_auth__pw_hash(struct dynsec__client *client, const char *password, unsigned char *password_hash, int password_hash_len, bool new_password);
int dynsec_auth__basic_auth_callback(int event, void *event_data, void *userdata);


/* ################################################################
 * #
 * # Client Functions
 * #
 * ################################################################ */

void dynsec_clients__cleanup(void);
int dynsec_clients__config_load(cJSON *tree);
int dynsec_clients__config_save(cJSON *tree);
int dynsec_clients__process_add_role(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_clients__process_create(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_clients__process_delete(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_clients__process_disable(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_clients__process_enable(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_clients__process_get(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_clients__process_list(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_clients__process_modify(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_clients__process_remove_role(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_clients__process_set_id(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_clients__process_set_password(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
struct dynsec__client *dynsec_clients__find(const char *username);


/* ################################################################
 * #
 * # Client List Functions
 * #
 * ################################################################ */

cJSON *dynsec_clientlist__all_to_json(struct dynsec__clientlist *base_clientlist);
int dynsec_clientlist__add(struct dynsec__clientlist **base_clientlist, struct dynsec__client *client, int priority);
void dynsec_clientlist__cleanup(struct dynsec__clientlist **base_clientlist);
void dynsec_clientlist__remove(struct dynsec__clientlist **base_clientlist, struct dynsec__client *client);
void dynsec_clientlist__kick_all(struct dynsec__clientlist *base_clientlist);


/* ################################################################
 * #
 * # Group Functions
 * #
 * ################################################################ */

void dynsec_groups__cleanup(void);
int dynsec_groups__config_load(cJSON *tree);
int dynsec_groups__add_client(const char *username, const char *groupname, int priority, bool update_config);
int dynsec_groups__config_save(cJSON *tree);
int dynsec_groups__process_add_client(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_groups__process_add_role(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_groups__process_create(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_groups__process_delete(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_groups__process_get(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_groups__process_list(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_groups__process_modify(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_groups__process_remove_client(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_groups__process_remove_role(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_groups__process_get_anonymous_group(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_groups__process_set_anonymous_group(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_groups__remove_client(const char *username, const char *groupname, bool update_config);
struct dynsec__group *dynsec_groups__find(const char *groupname);


/* ################################################################
 * #
 * # Group List Functions
 * #
 * ################################################################ */

cJSON *dynsec_grouplist__all_to_json(struct dynsec__grouplist *base_grouplist);
int dynsec_grouplist__add(struct dynsec__grouplist **base_grouplist, struct dynsec__group *group, int priority);
void dynsec_grouplist__cleanup(struct dynsec__grouplist **base_grouplist);
void dynsec_grouplist__remove(struct dynsec__grouplist **base_grouplist, struct dynsec__group *group);


/* ################################################################
 * #
 * # Role Functions
 * #
 * ################################################################ */

void dynsec_roles__cleanup(void);
int dynsec_roles__config_load(cJSON *tree);
int dynsec_roles__config_save(cJSON *tree);
int dynsec_roles__process_add_acl(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_roles__process_create(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_roles__process_delete(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_roles__process_get(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_roles__process_list(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_roles__process_modify(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
int dynsec_roles__process_remove_acl(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data);
struct dynsec__role *dynsec_roles__find(const char *rolename);


/* ################################################################
 * #
 * # Role List Functions
 * #
 * ################################################################ */

int dynsec_rolelist__client_add(struct dynsec__client *client, struct dynsec__role *role, int priority);
int dynsec_rolelist__client_remove(struct dynsec__client *client, struct dynsec__role *role);
int dynsec_rolelist__group_add(struct dynsec__group *group, struct dynsec__role *role, int priority);
void dynsec_rolelist__group_remove(struct dynsec__group *group, struct dynsec__role *role);
int dynsec_rolelist__load_from_json(cJSON *command, struct dynsec__rolelist **rolelist);
void dynsec_rolelist__cleanup(struct dynsec__rolelist **base_rolelist);
cJSON *dynsec_rolelist__all_to_json(struct dynsec__rolelist *base_rolelist);

#endif
