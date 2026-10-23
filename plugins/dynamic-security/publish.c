/*
Copyright (c) 2026 Mosquitto contributors

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/

#include "config.h"

#include <limits.h>
#include <math.h>
#include <string.h>

#include "dynamic_security.h"
#include "mosquitto/mqtt_protocol.h"

struct dynsec__publish_bucket {
	UT_hash_handle hh;
	time_t last_refill;
	double tokens;
	/* Identifies a checked publish until its tokens have been consumed. */
	uint64_t sequence;
	time_t last_warning;
	uint64_t rejected_messages;
	bool warning_logged;
	char name[];
};


/* ################################################################
 * #
 * # Configuration load and save
 * #
 * ################################################################ */


static int get_uint(cJSON *j_object, const char *name, uint32_t *value, uint32_t min, uint32_t max)
{
	cJSON *j_item = cJSON_GetObjectItem(j_object, name);

	/* Reject fractional values rather than silently truncating a policy. */
	if(!cJSON_IsNumber(j_item) || !isfinite(j_item->valuedouble)
			|| j_item->valuedouble < min || j_item->valuedouble > max
			|| floor(j_item->valuedouble) != j_item->valuedouble){
		return MOSQ_ERR_INVAL;
	}
	*value = (uint32_t)j_item->valuedouble;
	return MOSQ_ERR_SUCCESS;
}


int dynsec_publish__limits_load(cJSON *j_object, struct dynsec__publish_limits *limits)
{
	struct dynsec__publish_limits next = *limits;
	cJSON *j_rate = cJSON_GetObjectItem(j_object, "publishRateLimit");

	/* Missing fields preserve the current policy; validate into a copy so an
	 * invalid rate cannot partially apply a new payload-size limit. */
	if(cJSON_HasObjectItem(j_object, "maxPublishSize")
			&& get_uint(j_object, "maxPublishSize", &next.max_size, 0, MQTT_MAX_PAYLOAD)){
		return MOSQ_ERR_INVAL;
	}
	if(j_rate){
		if(cJSON_IsNull(j_rate)){
			next.messages = next.per_seconds = next.burst = 0;
		}else if(!cJSON_IsObject(j_rate)
				|| get_uint(j_rate, "messages", &next.messages, 1, INT_MAX)
				|| get_uint(j_rate, "perSeconds", &next.per_seconds, 1, INT_MAX)
				|| get_uint(j_rate, "burst", &next.burst, 1, INT_MAX)){
			return MOSQ_ERR_INVAL;
		}
	}
	*limits = next;
	return MOSQ_ERR_SUCCESS;
}


int dynsec_publish__limits_save(cJSON *j_object, const struct dynsec__publish_limits *limits)
{
	cJSON *j_rate;

	/* Omit disabled limits to preserve existing configuration and API output. */
	if(limits->max_size && cJSON_AddNumberToObject(j_object, "maxPublishSize", limits->max_size) == NULL){
		return MOSQ_ERR_NOMEM;
	}
	if(limits->messages){
		j_rate = cJSON_AddObjectToObject(j_object, "publishRateLimit");
		if(j_rate == NULL
				|| cJSON_AddNumberToObject(j_rate, "messages", limits->messages) == NULL
				|| cJSON_AddNumberToObject(j_rate, "perSeconds", limits->per_seconds) == NULL
				|| cJSON_AddNumberToObject(j_rate, "burst", limits->burst) == NULL){
			return MOSQ_ERR_NOMEM;
		}
	}
	return MOSQ_ERR_SUCCESS;
}


/* ################################################################
 * #
 * # Bucket lifetime
 * #
 * ################################################################ */


static void buckets_cleanup(struct dynsec__publish_bucket **buckets)
{
	struct dynsec__publish_bucket *bucket, *tmp;

	HASH_ITER(hh, *buckets, bucket, tmp){
		HASH_DEL(*buckets, bucket);
		mosquitto_free(bucket);
	}
}


void dynsec_publish__cleanup(struct dynsec__role *role)
{
	buckets_cleanup(&role->publish_buckets);
	buckets_cleanup(&role->anonymous_publish_buckets);
}


static void bucket_remove(struct dynsec__publish_bucket **buckets, const char *name)
{
	struct dynsec__publish_bucket *bucket;

	HASH_FIND_STR(*buckets, name, bucket);
	if(bucket){
		HASH_DEL(*buckets, bucket);
		mosquitto_free(bucket);
	}
}


void dynsec_publish__remove_client(struct dynsec__data *data, const char *username)
{
	struct dynsec__role *role, *tmp;

	HASH_ITER(hh, data->roles, role, tmp){
		bucket_remove(&role->publish_buckets, username);
	}
}


int dynsec_publish__disconnect_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_disconnect *ed = event_data;
	struct dynsec__data *data = userdata;
	struct dynsec__role *role, *tmp;
	const char *clientid;

	UNUSED(event);

	/* Named accounts retain their quota across reconnects. Anonymous clients
	 * have no persistent account, so their state lasts only for the connection. */
	if(!mosquitto_client_username(ed->client)){
		clientid = mosquitto_client_id(ed->client);
		if(clientid){
			HASH_ITER(hh, data->roles, role, tmp){
				bucket_remove(&role->anonymous_publish_buckets, clientid);
			}
		}
	}
	return MOSQ_ERR_SUCCESS;
}


/* ################################################################
 * #
 * # Publish checks
 * #
 * ################################################################ */


static void log_rejection(struct dynsec__role *role, struct dynsec__publish_bucket *bucket,
		const char *reason, time_t now)
{
	if(bucket->rejected_messages < UINT64_MAX){
		bucket->rejected_messages++;
	}
	if(!bucket->warning_logged || difftime(now, bucket->last_warning) >= 60.0){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"dynsec: publish limit exceeded | role=%s | client=%s | reason=%s | rejected=%llu since last warning",
				role->rolename, bucket->name, reason, (unsigned long long)bucket->rejected_messages);
		bucket->last_warning = now;
		bucket->warning_logged = true;
		bucket->rejected_messages = 0;
	}
}


static int check_role(struct dynsec__role *role, struct mosquitto_evt_message *ed,
		const char *name, bool anonymous, time_t now, uint64_t sequence, bool commit)
{
	const struct dynsec__publish_limits *limits = &role->publish_limits;
	struct dynsec__publish_bucket **buckets, *bucket;
	double elapsed;

	if(!limits->messages && (!limits->max_size || commit)){
		return MOSQ_ERR_SUCCESS;
	}

	buckets = anonymous ? &role->anonymous_publish_buckets : &role->publish_buckets;
	HASH_FIND_STR(*buckets, name, bucket);
	if(commit){
		/* A role may be assigned directly and through several groups. Charge it
		 * once, and only after every applicable role has accepted this message. */
		if(bucket && bucket->sequence == sequence){
			bucket->tokens -= 1.0;
			bucket->sequence = 0;
		}
		return MOSQ_ERR_SUCCESS;
	}
	if(bucket == NULL){
		bucket = mosquitto_calloc(1, sizeof(*bucket) + strlen(name) + 1);
		if(bucket == NULL){
			return MOSQ_ERR_NOMEM;
		}
		strcpy(bucket->name, name);
		bucket->tokens = limits->burst;
		bucket->last_refill = now;
		HASH_ADD_KEYPTR(hh, *buckets, bucket->name, strlen(bucket->name), bucket);
	}
	if(limits->max_size && ed->payloadlen > limits->max_size){
		log_rejection(role, bucket, "size", now);
		return MOSQ_ERR_QUOTA_EXCEEDED;
	}
	if(!limits->messages){
		return MOSQ_ERR_SUCCESS;
	}
	if(bucket->sequence == sequence){
		return MOSQ_ERR_SUCCESS;
	}

	/* Use the broker's time source with one-second resolution. Cap at the burst
	 * allowance so idle clients cannot accumulate extra credit. */
	if(now > bucket->last_refill){
		elapsed = difftime(now, bucket->last_refill);
		bucket->tokens = fmin(limits->burst,
				bucket->tokens + elapsed * limits->messages / limits->per_seconds);
		bucket->last_refill = now;
	}
	if(bucket->tokens < 1.0){
		log_rejection(role, bucket, "rate", now);
		return MOSQ_ERR_QUOTA_EXCEEDED;
	}
	bucket->sequence = sequence;
	return MOSQ_ERR_SUCCESS;
}


static int check_roles(struct dynsec__rolelist *roles, struct mosquitto_evt_message *ed,
		const char *name, bool anonymous, time_t now, uint64_t sequence, bool commit)
{
	struct dynsec__rolelist *role, *tmp;
	int rc;

	HASH_ITER(hh, roles, role, tmp){
		rc = check_role(role->role, ed, name, anonymous, now, sequence, commit);
		if(rc){
			return rc;
		}
	}
	return MOSQ_ERR_SUCCESS;
}


int dynsec_publish__callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_message *ed = event_data;
	struct dynsec__data *data = userdata;
	struct dynsec__client *client = NULL;
	struct dynsec__grouplist *group, *tmp;
	const char *username, *name;
	time_t now;
	int pass, rc;

	UNUSED(event);

	if(!ed->client){
		return MOSQ_ERR_SUCCESS;
	}
	username = mosquitto_client_username(ed->client);
	if(username){
		client = dynsec_clients__find(data, username);
		if(!client){
			return MOSQ_ERR_SUCCESS;
		}
		name = username;
	}else{
		if(!data->anonymous_group){
			return MOSQ_ERR_SUCCESS;
		}
		name = mosquitto_client_id(ed->client);
		if(!name){
			return MOSQ_ERR_SUCCESS;
		}
	}
	now = mosquitto_time();
	/* Zero marks a bucket already charged in the commit pass. */
	data->publish_sequence++;
	if(data->publish_sequence == 0){
		data->publish_sequence++;
	}

	/* Limits are cumulative across roles, independently of ACL priority. First
	 * check every quota, then consume tokens; a rejected publish consumes none. */
	for(pass=0; pass<2; pass++){
		if(client){
			rc = check_roles(client->rolelist, ed, name, false, now, data->publish_sequence, pass == 1);
			if(rc){
				return rc;
			}
			HASH_ITER(hh, client->grouplist, group, tmp){
				rc = check_roles(group->group->rolelist, ed, name, false, now, data->publish_sequence, pass == 1);
				if(rc){
					return rc;
				}
			}
		}else{
			rc = check_roles(data->anonymous_group->rolelist, ed, name, true, now, data->publish_sequence, pass == 1);
			if(rc){
				return rc;
			}
		}
	}
	return MOSQ_ERR_SUCCESS;
}
