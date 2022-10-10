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

#include "config.h"

#include "dynamic_security.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"

typedef int (*MOSQ_FUNC_acl_check)(struct dynsec__data *data, struct mosquitto_evt_acl_check *, struct dynsec__rolelist *);

/* FIXME - CACHE! */

/* ################################################################
 * #
 * # ACL check - publish broker to client
 * #
 * ################################################################ */

static int acl_check_publish_c_recv(struct dynsec__data *data, struct mosquitto_evt_acl_check *ed, struct dynsec__rolelist *base_rolelist)
{
	struct dynsec__rolelist *rolelist, *rolelist_tmp = NULL;
	struct dynsec__acl *acl, *acl_tmp = NULL;
	bool result;
	const char *clientid, *username;

	UNUSED(data);

	clientid = mosquitto_client_id(ed->client);
	username = mosquitto_client_username(ed->client);

	HASH_ITER(hh, base_rolelist, rolelist, rolelist_tmp){
		HASH_ITER(hh, rolelist->role->acls.publish_c_recv, acl, acl_tmp){
			mosquitto_topic_matches_sub_with_pattern(acl->topic, ed->topic, clientid, username, &result);
			if(result){
				if(acl->allow){
					return MOSQ_ERR_SUCCESS;
				}else{
					return MOSQ_ERR_ACL_DENIED;
				}
			}
		}
	}
	return MOSQ_ERR_NOT_FOUND;
}


/* ################################################################
 * #
 * # ACL check - publish client to broker
 * #
 * ################################################################ */

static int acl_check_publish_c_send(struct dynsec__data *data, struct mosquitto_evt_acl_check *ed, struct dynsec__rolelist *base_rolelist)
{
	struct dynsec__rolelist *rolelist, *rolelist_tmp = NULL;
	struct dynsec__acl *acl, *acl_tmp = NULL;
	bool result;
	const char *clientid, *username;

	UNUSED(data);

	clientid = mosquitto_client_id(ed->client);
	username = mosquitto_client_username(ed->client);

	HASH_ITER(hh, base_rolelist, rolelist, rolelist_tmp){
		HASH_ITER(hh, rolelist->role->acls.publish_c_send, acl, acl_tmp){
			mosquitto_topic_matches_sub_with_pattern(acl->topic, ed->topic, clientid, username, &result);
			if(result){
				if(acl->allow){
					return MOSQ_ERR_SUCCESS;
				}else{
					return MOSQ_ERR_ACL_DENIED;
				}
			}
		}
	}
	return MOSQ_ERR_NOT_FOUND;
}


/* ################################################################
 * #
 * # ACL check - subscribe
 * #
 * ################################################################ */

static int acl_check_subscribe(struct dynsec__data *data, struct mosquitto_evt_acl_check *ed, struct dynsec__rolelist *base_rolelist)
{
	struct dynsec__rolelist *rolelist, *rolelist_tmp = NULL;
	struct dynsec__acl *acl, *acl_tmp = NULL;
	size_t len;
	bool result;
	const char *clientid, *username;
	bool has_wildcard;

	UNUSED(data);

	len = strlen(ed->topic);
	has_wildcard = (strpbrk(ed->topic, "+#") != NULL);

	clientid = mosquitto_client_id(ed->client);
	username = mosquitto_client_username(ed->client);

	HASH_ITER(hh, base_rolelist, rolelist, rolelist_tmp){
		if(rolelist->role->allow_wildcard_subs == false && has_wildcard == true){
			return MOSQ_ERR_ACL_DENIED;
		}
		HASH_FIND(hh, rolelist->role->acls.subscribe_literal, ed->topic, len, acl);
		if(acl){
			if(acl->allow){
				return MOSQ_ERR_SUCCESS;
			}else{
				return MOSQ_ERR_ACL_DENIED;
			}
		}
		HASH_ITER(hh, rolelist->role->acls.subscribe_pattern, acl, acl_tmp){
			mosquitto_sub_matches_acl_with_pattern(acl->topic, ed->topic, clientid, username, &result);
			if(result){
				if(acl->allow){
					return MOSQ_ERR_SUCCESS;
				}else{
					return MOSQ_ERR_ACL_DENIED;
				}
			}
		}
	}
	return MOSQ_ERR_NOT_FOUND;
}


/* ################################################################
 * #
 * # ACL check - unsubscribe
 * #
 * ################################################################ */

static int acl_check_unsubscribe(struct dynsec__data *data, struct mosquitto_evt_acl_check *ed, struct dynsec__rolelist *base_rolelist)
{
	struct dynsec__rolelist *rolelist, *rolelist_tmp = NULL;
	struct dynsec__acl *acl, *acl_tmp = NULL;
	size_t len;
	bool result;
	const char *clientid, *username;

	UNUSED(data);

	len = strlen(ed->topic);

	clientid = mosquitto_client_id(ed->client);
	username = mosquitto_client_username(ed->client);

	HASH_ITER(hh, base_rolelist, rolelist, rolelist_tmp){
		HASH_FIND(hh, rolelist->role->acls.unsubscribe_literal, ed->topic, len, acl);
		if(acl){
			if(acl->allow){
				return MOSQ_ERR_SUCCESS;
			}else{
				return MOSQ_ERR_ACL_DENIED;
			}
		}
		HASH_ITER(hh, rolelist->role->acls.unsubscribe_pattern, acl, acl_tmp){
			mosquitto_sub_matches_acl_with_pattern(acl->topic, ed->topic, clientid, username, &result);
			if(result){
				if(acl->allow){
					return MOSQ_ERR_SUCCESS;
				}else{
					return MOSQ_ERR_ACL_DENIED;
				}
			}
		}
	}
	return MOSQ_ERR_NOT_FOUND;
}


/* ################################################################
 * #
 * # ACL check - generic check
 * #
 * ################################################################ */

static int acl_check(struct dynsec__data *data, struct mosquitto_evt_acl_check *ed, MOSQ_FUNC_acl_check check, bool acl_default_access)
{
	struct dynsec__client *client;
	struct dynsec__grouplist *grouplist, *grouplist_tmp = NULL;
	const char *username;
	int rc;

	username = mosquitto_client_username(ed->client);

	if(username){
		client = dynsec_clients__find(data, username);
		if(client == NULL) return MOSQ_ERR_PLUGIN_DEFER;

		/* Client roles */
		rc = check(data, ed, client->rolelist);
		if(rc != MOSQ_ERR_NOT_FOUND){
			return rc;
		}

		HASH_ITER(hh, client->grouplist, grouplist, grouplist_tmp){
			rc = check(data, ed, grouplist->group->rolelist);
			if(rc != MOSQ_ERR_NOT_FOUND){
				return rc;
			}
		}
	}else if(data->anonymous_group){
		/* If we have a group for anonymous users, use that for checking. */
		rc = check(data, ed, data->anonymous_group->rolelist);
		if(rc != MOSQ_ERR_NOT_FOUND){
			return rc;
		}
	}

	if(acl_default_access == false){
		return MOSQ_ERR_PLUGIN_DEFER;
	}else{
		if(!strncmp(ed->topic, "$CONTROL", strlen("$CONTROL"))){
			/* We never give fall through access to $CONTROL topics, they must
			 * be granted explicitly. */
			return MOSQ_ERR_PLUGIN_DEFER;
		}else{
			return MOSQ_ERR_SUCCESS;
		}
	}
}


/* ################################################################
 * #
 * # ACL check - plugin callback
 * #
 * ################################################################ */

int dynsec__acl_check_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_acl_check *ed = event_data;
	struct dynsec__data *data = userdata;

	UNUSED(event);
	UNUSED(userdata);

	/* ACL checks are made in the order below until a match occurs, at which
	 * point the decision is made.
	 *
	 * User roles in priority order highest to lowest.
	 *    Roles have their ACLs checked in priority order, highest to lowest
	 * Groups are processed in priority order highest to lowest
	 *    Group roles are processed in priority order, highest to lowest
	 *       Roles have their ACLs checked in priority order, highest to lowest
	 */

	switch(ed->access){
		case MOSQ_ACL_SUBSCRIBE:
			return acl_check(data, event_data, acl_check_subscribe, data->default_access.subscribe);
			break;
		case MOSQ_ACL_UNSUBSCRIBE:
			return acl_check(data, event_data, acl_check_unsubscribe, data->default_access.unsubscribe);
			break;
		case MOSQ_ACL_WRITE: /* Client to broker */
			return acl_check(data, event_data, acl_check_publish_c_send, data->default_access.publish_c_send);
			break;
		case MOSQ_ACL_READ:
			return acl_check(data, event_data, acl_check_publish_c_recv, data->default_access.publish_c_recv);
			break;
		default:
			return MOSQ_ERR_PLUGIN_DEFER;
	}
	return MOSQ_ERR_PLUGIN_DEFER;
}
