/*
Copyright (c) 2009-2019 Roger Light <roger@atchoo.org>

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

#include "mosquitto.h"
#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"

#ifdef WITH_BRIDGE
static int bridge__create_remap_topic(const char *prefix, const char *topic, char **remap_topic)
{
	size_t len;

	if(prefix){
		if(topic){
			len = strlen(topic) + strlen(prefix)+1;
			*remap_topic = mosquitto__malloc(len+1);
			if(!(*remap_topic)){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				return MOSQ_ERR_NOMEM;
			}
			snprintf(*remap_topic, len+1, "%s%s", prefix, topic);
			(*remap_topic)[len] = '\0';
		}else{
			*remap_topic = mosquitto__strdup(prefix);
			if(!(*remap_topic)){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				return MOSQ_ERR_NOMEM;
			}
		}
	}else{
		*remap_topic = mosquitto__strdup(topic);
		if(!(*remap_topic)){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
	}
	return MOSQ_ERR_SUCCESS;
}


static int bridge__create_prefix(char **full_prefix, const char *topic, const char *prefix, const char *direction)
{
	size_t len;

	if(mosquitto_pub_topic_check(prefix) != MOSQ_ERR_SUCCESS){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge topic local prefix '%s'.", prefix);
		return MOSQ_ERR_INVAL;
	}

	if(topic){
		len = strlen(topic) + strlen(prefix) + 1;
	}else{
		len = strlen(prefix) + 1;
	}
	*full_prefix = mosquitto__malloc(len);
	if(*full_prefix == NULL){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}

	if(topic){
		/* Print full_prefix+pattern to check for validity */
		snprintf(*full_prefix, len, "%s%s", prefix, topic);
	}else{
		snprintf(*full_prefix, len, "%s", prefix);
	}

	if(mosquitto_sub_topic_check(*full_prefix) != MOSQ_ERR_SUCCESS){
		log__printf(NULL, MOSQ_LOG_ERR,
				"Error: Invalid bridge topic %s prefix and pattern combination '%s'.",
				direction, *full_prefix);

		return MOSQ_ERR_INVAL;
	}

	/* Print just the prefix for storage */
	snprintf(*full_prefix, len, "%s", prefix);

	return MOSQ_ERR_SUCCESS;
}


/* topic <topic> [[[out | in | both] qos-level] local-prefix remote-prefix] */
int bridge__add_topic(struct mosquitto__bridge *bridge, const char *topic, enum mosquitto__bridge_direction direction, uint8_t qos, const char *local_prefix, const char *remote_prefix)
{
	struct mosquitto__bridge_topic *topics;
	struct mosquitto__bridge_topic *cur_topic;


	if(bridge == NULL) return MOSQ_ERR_INVAL;
	if(direction != bd_out && direction != bd_in && direction != bd_both){
		return MOSQ_ERR_INVAL;
	}
	if(qos > 2){
		return MOSQ_ERR_INVAL;
	}
	if(local_prefix && mosquitto_pub_topic_check(local_prefix)){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge topic local prefix '%s'.", local_prefix);
		return MOSQ_ERR_INVAL;
	}
	if(remote_prefix && mosquitto_pub_topic_check(remote_prefix)){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge topic remote prefix '%s'.", remote_prefix);
		return MOSQ_ERR_INVAL;
	}
	if((topic == NULL || !strcmp(topic, "\"\"")) &&
			(local_prefix == NULL || remote_prefix == NULL)){

		log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge remapping.");
		return MOSQ_ERR_INVAL;
	}


	bridge->topic_count++;
	topics = mosquitto__realloc(bridge->topics,
				sizeof(struct mosquitto__bridge_topic)*(size_t)bridge->topic_count);

	if(topics == NULL){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}
	bridge->topics = topics;

	cur_topic = &bridge->topics[bridge->topic_count-1];
	cur_topic->direction = direction;
	cur_topic->qos = qos;
	cur_topic->local_prefix = NULL;
	cur_topic->remote_prefix = NULL;

	if(topic == NULL || !strcmp(topic, "\"\"")){
		cur_topic->topic = NULL;
	}else{
		cur_topic->topic = mosquitto__strdup(topic);
		if(cur_topic->topic == NULL){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
	}

	if(local_prefix || remote_prefix){
		bridge->topic_remapping = true;
		if(local_prefix){
			if(bridge__create_prefix(&cur_topic->local_prefix, cur_topic->topic, local_prefix, "local")){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				return MOSQ_ERR_NOMEM;
			}
		}
		if(remote_prefix){
			if(bridge__create_prefix(&cur_topic->remote_prefix, cur_topic->topic, remote_prefix, "local")){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				return MOSQ_ERR_NOMEM;
			}
		}
	}

	if(bridge__create_remap_topic(cur_topic->local_prefix,
			cur_topic->topic, &cur_topic->local_topic)){

		return MOSQ_ERR_INVAL;
	}

	if(bridge__create_remap_topic(cur_topic->remote_prefix,
			cur_topic->topic, &cur_topic->remote_topic)){

		return MOSQ_ERR_INVAL;
	}

	return MOSQ_ERR_SUCCESS;
}


int bridge__remap_topic_in(struct mosquitto *context, char **topic)
{
	struct mosquitto__bridge_topic *cur_topic;
	char *topic_temp;
	int i;
	size_t len;
	int rc;
	bool match;

	if(context->bridge && context->bridge->topics && context->bridge->topic_remapping){
		for(i=0; i<context->bridge->topic_count; i++){
			cur_topic = &context->bridge->topics[i];
			if((cur_topic->direction == bd_both || cur_topic->direction == bd_in)
					&& (cur_topic->remote_prefix || cur_topic->local_prefix)){

				/* Topic mapping required on this topic if the message matches */

				rc = mosquitto_topic_matches_sub(cur_topic->remote_topic, *topic, &match);
				if(rc){
					mosquitto__free(*topic);
					return rc;
				}
				if(match){
					if(cur_topic->remote_prefix){
						/* This prefix needs removing. */
						if(!strncmp(cur_topic->remote_prefix, *topic, strlen(cur_topic->remote_prefix))){
							topic_temp = mosquitto__strdup((*topic)+strlen(cur_topic->remote_prefix));
							if(!topic_temp){
								mosquitto__free(*topic);
								return MOSQ_ERR_NOMEM;
							}
							mosquitto__free(*topic);
							*topic = topic_temp;
						}
					}

					if(cur_topic->local_prefix){
						/* This prefix needs adding. */
						len = strlen(*topic) + strlen(cur_topic->local_prefix)+1;
						topic_temp = mosquitto__malloc(len+1);
						if(!topic_temp){
							mosquitto__free(*topic);
							return MOSQ_ERR_NOMEM;
						}
						snprintf(topic_temp, len, "%s%s", cur_topic->local_prefix, *topic);
						topic_temp[len] = '\0';

						mosquitto__free(*topic);
						*topic = topic_temp;
					}
					break;
				}
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
}

#endif
