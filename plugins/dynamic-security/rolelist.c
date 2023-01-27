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

#include <cjson/cJSON.h>
#include <stdio.h>
#include <string.h>
#include <uthash.h>
#include <utlist.h>
#include <yaml.h>

#include "dynamic_security.h"
#include "json_help.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"


/* ################################################################
 * #
 * # Utility functions
 * #
 * ################################################################ */

static int rolelist_cmp(void *a, void *b)
{
	int prio;
	struct dynsec__rolelist *rolelist_a = a;
	struct dynsec__rolelist *rolelist_b = b;

	prio = rolelist_b->priority - rolelist_a->priority;
	if(prio == 0){
		return strcmp(rolelist_a->rolename, rolelist_b->rolename);
	}else{
		return prio;
	}
}


static void dynsec_rolelist__free_item(struct dynsec__rolelist **base_rolelist, struct dynsec__rolelist *rolelist)
{
	HASH_DELETE(hh, *base_rolelist, rolelist);
	mosquitto_free(rolelist);
}

void dynsec_rolelist__cleanup(struct dynsec__rolelist **base_rolelist)
{
	struct dynsec__rolelist *rolelist, *rolelist_tmp;

	HASH_ITER(hh, *base_rolelist, rolelist, rolelist_tmp){
		dynsec_rolelist__free_item(base_rolelist, rolelist);
	}
}

int dynsec_rolelist__remove_role(struct dynsec__rolelist **base_rolelist, const struct dynsec__role *role)
{
	struct dynsec__rolelist *found_rolelist;

	HASH_FIND(hh, *base_rolelist, role->rolename, strlen(role->rolename), found_rolelist);
	if(found_rolelist){
		dynsec_rolelist__free_item(base_rolelist, found_rolelist);
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_NOT_FOUND;
	}
}


int dynsec_rolelist__client_remove(struct dynsec__client *client, struct dynsec__role *role)
{
	int rc;
	struct dynsec__clientlist *found_clientlist;

	rc = dynsec_rolelist__remove_role(&client->rolelist, role);
	if(rc) return rc;

	HASH_FIND(hh, role->clientlist, client->username, strlen(client->username), found_clientlist);
	if(found_clientlist){
		HASH_DELETE(hh, role->clientlist, found_clientlist);
		mosquitto_free(found_clientlist);
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_NOT_FOUND;
	}
}


void dynsec_rolelist__group_remove(struct dynsec__group *group, struct dynsec__role *role)
{
	dynsec_rolelist__remove_role(&group->rolelist, role);
	dynsec_grouplist__remove(&role->grouplist, group);
}


int dynsec_rolelist__add(struct dynsec__rolelist **base_rolelist, struct dynsec__role *role, int priority)
{
	struct dynsec__rolelist *rolelist;
	size_t rolename_len;

	if(role == NULL) return MOSQ_ERR_INVAL;
	rolename_len = strlen(role->rolename);
	if(rolename_len == 0) return MOSQ_ERR_INVAL;

	HASH_FIND(hh, *base_rolelist, role->rolename, rolename_len, rolelist);
	if(rolelist){
		return MOSQ_ERR_ALREADY_EXISTS;
	}else{
		rolelist = mosquitto_calloc(1, sizeof(struct dynsec__rolelist) + rolename_len + 1);
		if(rolelist == NULL) return MOSQ_ERR_NOMEM;

		rolelist->role = role;
		rolelist->priority = priority;
		strncpy(rolelist->rolename, role->rolename, rolename_len+1);
		HASH_ADD_INORDER(hh, *base_rolelist, rolename, rolename_len, rolelist, rolelist_cmp);
		return MOSQ_ERR_SUCCESS;
	}
}


int dynsec_rolelist__client_add(struct dynsec__client *client, struct dynsec__role *role, int priority)
{
	struct dynsec__rolelist *rolelist;
	int rc;

	rc = dynsec_rolelist__add(&client->rolelist, role, priority);
	if(rc) return rc;

	HASH_FIND(hh, client->rolelist, role->rolename, strlen(role->rolename), rolelist);
	if(rolelist == NULL){
		/* This should never happen because the above add_role succeeded. */
		return MOSQ_ERR_UNKNOWN;
	}

	rc = dynsec_clientlist__add(&role->clientlist, client, priority);
	if(rc){
		dynsec_rolelist__remove_role(&client->rolelist, role);
	}

	return rc;
}


int dynsec_rolelist__group_add(struct dynsec__group *group, struct dynsec__role *role, int priority)
{
	int rc;

	rc = dynsec_rolelist__add(&group->rolelist, role, priority);
	if(rc) return rc;

	rc = dynsec_grouplist__add(&role->grouplist, group, priority);
	if(rc){
		dynsec_rolelist__remove_role(&group->rolelist, role);
	}
	return rc;
}

