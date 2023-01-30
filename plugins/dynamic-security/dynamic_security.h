#ifndef DYNAMIC_SECURITY_H
#define DYNAMIC_SECURITY_H
/*
Copyright (c) 2020-2021 Roger Light <roger@atchoo.org>

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

#include <cjson/cJSON.h>
#include <uthash.h>
#include "mosquitto.h"
#include "password_mosq.h"
#include "base64_mosq.h"
#include "control_common.h"
#include "yaml.h"

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
	struct dynsec__role *role;
	int priority;
	char rolename[];
};

struct dynsec__kicklist{
	struct dynsec__kicklist *next, *prev;
	char username[];
};

struct dynsec__client{
	UT_hash_handle hh;
	struct mosquitto_pw pw;
	struct dynsec__rolelist *rolelist;
	struct dynsec__grouplist *grouplist;
	char *clientid;
	char *text_name;
	char *text_description;
	bool disabled;
	char username[];
};

struct dynsec__group{
	UT_hash_handle hh;
	struct dynsec__rolelist *rolelist;
	struct dynsec__clientlist *clientlist;
	char *text_name;
	char *text_description;
	char groupname[];
};


struct dynsec__acl{
	UT_hash_handle hh;
	int priority;
	bool allow;
	char topic[];
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
	char *text_name;
	char *text_description;
	bool allow_wildcard_subs;
	char rolename[];
};

struct dynsec__acl_default_access{
	bool publish_c_send;
	bool publish_c_recv;
	bool subscribe;
	bool unsubscribe;
};

enum dynsec_pw_init_mode{
	dpwim_file = 1,
	dpwim_env = 2,
	dpwim_random = 3,
};

enum plugin_config_format{
    CONFIG_FORMAT_AUTO = 0,
    CONFIG_FORMAT_JSON = 1,
#ifdef WITH_YAML
    CONFIG_FORMAT_YAML = 2,
#endif
};

struct dynsec__data{
	char *config_file;
    int config_format;
	char *password_init_file;
	struct dynsec__client *clients;
	struct dynsec__group *groups;
	struct dynsec__role *roles;
	struct dynsec__group *anonymous_group;
	struct dynsec__kicklist *kicklist;
	struct dynsec__acl_default_access default_access;
	int init_mode;
	bool need_save;
};

/* ################################################################
 * #
 * # Plugin Functions
 * #
 * ################################################################ */

int dynsec__config_init(struct dynsec__data *data);
void dynsec__config_save(struct dynsec__data *data);
void dynsec__config_batch_save(struct dynsec__data *data);
int dynsec__config_load(struct dynsec__data *data);
int dynsec__config_load_yaml(struct dynsec__data *data, FILE* fptr);
int dynsec__config_load_json(struct dynsec__data *data, FILE* fptr);
char *dynsec__config_to_json(struct dynsec__data *data);
int dynsec__config_from_json(struct dynsec__data *data, const char *json_str);
void dynsec__command_reply(cJSON *j_responses, struct mosquitto *context, const char *command, const char *error, const char *correlation_data);
int dynsec_control_callback(int event, void *event_data, void *userdata);
int dynsec__write_yaml_config(FILE* fptr, void *user_data);
int dynsec__write_json_config(FILE* fptr, void* user_data);

/* ################################################################
 * #
 * # ACL Functions
 * #
 * ################################################################ */

int dynsec__acl_check_callback(int event, void *event_data, void *userdata);
int dynsec__process_set_default_acl_access(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec__process_get_default_acl_access(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_acls__to_json(cJSON *j_role, struct dynsec__role *role);
int dynsec_acls__load_json(cJSON *j_acls, const char *key, struct dynsec__acl **acllist);
int dynsec_acls__load_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__acls* acls);
int dynsec__acls__to_yaml(yaml_emitter_t *emitter, yaml_event_t *event, struct dynsec__role *role);

/* ################################################################
 * #
 * # ACL List Functions
 * #
 * ################################################################ */

bool dynsec_acllist__add(struct dynsec__acl **acllist, struct dynsec__acl *acl);
int dynsec_acllist__to_json(cJSON *j_array, struct dynsec__acl *acl, const char *acl_type);
int dynsec_acllist__to_yaml(yaml_emitter_t *emitter, yaml_event_t *event, struct dynsec__acl *acl, const char *acl_type);


/* ################################################################
 * #
 * # Auth Functions
 * #
 * ################################################################ */

int dynsec_auth__pw_hash(struct dynsec__client *client, const char *password, unsigned char *password_hash, int password_hash_len, bool new_password);
int dynsec_auth__basic_auth_callback(int event, void *event_data, void *userdata);


/* ################################################################
 * #
 * # Client Functions
 * #
 * ################################################################ */

void dynsec_clients__cleanup(struct dynsec__data *data);
int dynsec_clients__config_load_json(struct dynsec__data *data, cJSON *tree);
int dynsec_clients__config_load_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__data *data);
int dynsec_clients__config_save_json(struct dynsec__data *data, cJSON *tree);
int dynsec_clients__config_save_yaml(yaml_emitter_t* emitter, yaml_event_t* event, struct dynsec__data *data);
int dynsec_clients__process_add_role(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_clients__process_create(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_clients__process_delete(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_clients__process_disable(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_clients__process_enable(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_clients__process_get(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_clients__process_list(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_clients__process_modify(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_clients__process_remove_role(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_clients__process_set_id(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_clients__process_set_password(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
struct dynsec__client *dynsec_clients__find(struct dynsec__data *data, const char *username);
bool dynsec_clients__insert(struct dynsec__data *data, struct dynsec__client *client);
struct dynsec__client *dynsec_clients__create(const char *username);

/* ################################################################
 * #
 * # Client List Functions
 * #
 * ################################################################ */

cJSON *dynsec_clientlist__all_to_json(struct dynsec__clientlist *base_clientlist);
int dynsec_clientlist__all_to_yaml(struct dynsec__clientlist *clientlist, yaml_emitter_t* emitter, yaml_event_t *event);
int dynsec_clientlist__add(struct dynsec__clientlist **base_clientlist, struct dynsec__client *client, int priority);
void dynsec_clientlist__cleanup(struct dynsec__clientlist **base_clientlist);
void dynsec_clientlist__remove(struct dynsec__clientlist **base_clientlist, struct dynsec__client *client);
void dynsec_clientlist__kick_all(struct dynsec__data *data, struct dynsec__clientlist *base_clientlist);
int dynsec_clientlist__load_from_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__data *data, struct dynsec__clientlist **clientlist);


/* ################################################################
 * #
 * # Group Functions
 * #
 * ################################################################ */

void dynsec_groups__cleanup(struct dynsec__data *data);
int dynsec_groups__config_load_json(struct dynsec__data *data, cJSON *tree);
int dynsec_groups__config_load_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__data *data);
int dynsec_groups__add_client(struct dynsec__data *data, const char *username, const char *groupname, int priority, bool update_config);
int dynsec_groups__config_save_json(struct dynsec__data *data, cJSON *tree);
int dynsec_groups__config_save_yaml(yaml_emitter_t* emitter, yaml_event_t* event, struct dynsec__data *data);
int dynsec_groups__process_add_client(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_groups__process_add_role(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_groups__process_create(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_groups__process_delete(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_groups__process_get(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_groups__process_list(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_groups__process_modify(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_groups__process_remove_client(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_groups__process_remove_role(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_groups__process_get_anonymous_group(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_groups__process_set_anonymous_group(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_groups__remove_client(struct dynsec__data *data, const char *username, const char *groupname, bool update_config);
struct dynsec__group *dynsec_groups__find(struct dynsec__data *data, const char *groupname);
struct dynsec__group *dynsec_groups__create(const char *groupname);
bool dynsec_groups__insert(struct dynsec__data *data, struct dynsec__group *group);

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

void dynsec_roles__cleanup(struct dynsec__data *data);
int dynsec_roles__config_load_json(struct dynsec__data *data, cJSON *tree);
int dynsec_roles__config_load_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__data *data);
int dynsec_roles__config_save_json(struct dynsec__data *data, cJSON *tree);
int dynsec_roles__config_save_yaml(yaml_emitter_t *emitter, yaml_event_t *event, struct dynsec__data *data);
int dynsec_roles__process_add_acl(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_roles__process_create(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_roles__process_delete(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_roles__process_get(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_roles__process_list(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_roles__process_modify(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
int dynsec_roles__process_remove_acl(struct dynsec__data *data, struct control_cmd *cmd, struct mosquitto *context);
struct dynsec__role *dynsec_roles__find(struct dynsec__data *data, const char *rolename);
struct dynsec__role *dynsec_roles__create(const char *rolename);
bool dynsec_roles__insert(struct dynsec__data *data, struct dynsec__role* role);


/* ################################################################
 * #
 * # Role List Functions
 * #
 * ################################################################ */

int dynsec_rolelist__add(struct dynsec__rolelist **base_rolelist, struct dynsec__role *role, int priority);
int dynsec_rolelist__remove_role(struct dynsec__rolelist **base_rolelist, const struct dynsec__role *role);
int dynsec_rolelist__client_add(struct dynsec__client *client, struct dynsec__role *role, int priority);
int dynsec_rolelist__client_remove(struct dynsec__client *client, struct dynsec__role *role);
int dynsec_rolelist__group_add(struct dynsec__group *group, struct dynsec__role *role, int priority);
void dynsec_rolelist__group_remove(struct dynsec__group *group, struct dynsec__role *role);
int dynsec_rolelist__load_from_json(struct dynsec__data *data, cJSON *command, struct dynsec__rolelist **rolelist);
int dynsec_rolelist__load_from_yaml(yaml_parser_t *parser, yaml_event_t *event, struct dynsec__data *data, struct dynsec__rolelist **rolelist);
void dynsec_rolelist__cleanup(struct dynsec__rolelist **base_rolelist);
cJSON *dynsec_rolelist__all_to_json(struct dynsec__rolelist *base_rolelist);
int dynsec_rolelist__all_to_yaml(struct dynsec__rolelist *rolelist, yaml_emitter_t *emitter, yaml_event_t *event);

/* ################################################################
 * #
 * # Kick List Functions
 * #
 * ################################################################ */

int dynsec_kicklist__add(struct dynsec__data *data, const char *username);
void dynsec_kicklist__kick(struct dynsec__data *data);
int dynsec__tick_callback(int event, void *event_data, void *userdata);
void dynsec_kicklist__cleanup(struct dynsec__data *data);

#endif
