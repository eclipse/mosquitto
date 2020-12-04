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

#include "config.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <uthash.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "json_help.h"

#include "dynamic_security.h"

/* ################################################################
 * #
 * # Plugin global variables
 * #
 * ################################################################ */

/* ################################################################
 * #
 * # Function declarations
 * #
 * ################################################################ */

/* ################################################################
 * #
 * # Local variables
 * #
 * ################################################################ */

/* ################################################################
 * #
 * # Utility functions
 * #
 * ################################################################ */

static int dynsec_grouplist__cmp(void *a, void *b)
{
	int prio;
	struct dynsec__grouplist *grouplist_a = a;
	struct dynsec__grouplist *grouplist_b = b;

	prio = grouplist_b->priority - grouplist_a->priority;
	if(prio == 0){
		return strcmp(grouplist_a->group->groupname, grouplist_b->group->groupname);
	}else{
		return prio;
	}
}

cJSON *dynsec_grouplist__all_to_json(struct dynsec__grouplist *base_grouplist)
{
	struct dynsec__grouplist *grouplist, *grouplist_tmp;
	cJSON *j_groups, *j_group;

	j_groups = cJSON_CreateArray();
	if(j_groups == NULL) return NULL;

	HASH_ITER(hh, base_grouplist, grouplist, grouplist_tmp){
		j_group = cJSON_CreateObject();
		if(j_group == NULL){
			cJSON_Delete(j_groups);
			return NULL;
		}
		cJSON_AddItemToArray(j_groups, j_group);

		if(cJSON_AddStringToObject(j_group, "groupname", grouplist->group->groupname) == NULL
				|| (grouplist->priority != -1 && cJSON_AddIntToObject(j_group, "priority", grouplist->priority) == NULL)
				){

			cJSON_Delete(j_groups);
			return NULL;
		}
	}
	return j_groups;
}



int dynsec_grouplist__add(struct dynsec__grouplist **base_grouplist, struct dynsec__group *group, int priority)
{
	struct dynsec__grouplist *grouplist;

	HASH_FIND(hh, *base_grouplist, group->groupname, strlen(group->groupname), grouplist);
	if(grouplist != NULL){
		/* Group is already in the list */
		return MOSQ_ERR_SUCCESS;
	}

	grouplist = mosquitto_malloc(sizeof(struct dynsec__grouplist));
	if(grouplist == NULL){
		return MOSQ_ERR_NOMEM;
	}

	grouplist->group = group;
	grouplist->priority = priority;
	HASH_ADD_KEYPTR_INORDER(hh, *base_grouplist, grouplist->group->groupname, strlen(grouplist->group->groupname), grouplist, dynsec_grouplist__cmp);

	return MOSQ_ERR_SUCCESS;
}


void dynsec_grouplist__cleanup(struct dynsec__grouplist **base_grouplist)
{
	struct dynsec__grouplist *grouplist, *grouplist_tmp;

	HASH_ITER(hh, *base_grouplist, grouplist, grouplist_tmp){
		HASH_DELETE(hh, *base_grouplist, grouplist);
		mosquitto_free(grouplist);
	}
}


void dynsec_grouplist__remove(struct dynsec__grouplist **base_grouplist, struct dynsec__group *group)
{
	struct dynsec__grouplist *grouplist;

	HASH_FIND(hh, *base_grouplist, group->groupname, strlen(group->groupname), grouplist);
	if(grouplist){
		HASH_DELETE(hh, *base_grouplist, grouplist);
		mosquitto_free(grouplist);
	}
}
