/*
Copyright (c) 2017-2020 Tifaifai Maupiti <tifaifai.maupiti@gmail.com>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

Contributor:
   Tifaifai Maupiti - Initial implementation and documentation.
*/
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#ifdef WITH_EPOLL
#include <sys/epoll.h>
#endif

#ifdef WITH_CJSON
#  include <cjson/cJSON.h>
#endif

#ifndef WIN32
#include <unistd.h>
#include <strings.h>
#else
#include <process.h>
#include <winsock2.h>
#define snprintf sprintf_s
#define strncasecmp _strnicmp
#endif

#include "mosquitto_broker_internal.h"
#include "mqtt_protocol.h"
#include "memory_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "util_mosq.h"

extern struct mosquitto_db int_db;

static int config__check(struct mosquitto__config *config);

// mux_epoll__add_in temporaly function in wait (develop branch of Roger Light)
int mux_epoll__add_in(struct mosquitto_db *db, struct mosquitto *context)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = context->sock;
	if (epoll_ctl(db->epollfd, EPOLL_CTL_ADD, context->sock, &ev) == -1) {
		log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll accepting: %s", strerror(errno));
	}
	context->events = EPOLLIN;
	return MOSQ_ERR_SUCCESS;
}

int bridge__dynamic_analyse(struct mosquitto_db *db, char *topic, void* payload, uint32_t payloadlen)
{
	int rc;
	int *index;

	struct mosquitto__config config;
	config__init(&int_db, &config);

	index = (int*) mosquitto__malloc(sizeof(int));
	*index = -1;

	if(strncmp("$SYS/broker/bridge/new",topic,22)==0){
		rc = bridge__dynamic_parse_payload_new_json(db, payload, &config);
		if(rc != 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to parse PUBLISH for bridge dynamic.");
			mosquitto__free(index);
			return MOSQ_ERR_BRIDGE_DYNA;
		}
		rc = config__check(&config);
		if(rc != 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to parse PUBLISH.");
			mosquitto__free(index);
			return MOSQ_ERR_BRIDGE_DYNA;
		}
		bridge__new(db, &(config.bridges[config.bridge_count-1]));
		if(rc != 0){
			log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Unable to connect to bridge %s.",
					config.bridges[config.bridge_count-1].name);
			mosquitto__free(index);
			return MOSQ_ERR_BRIDGE_DYNA;
		}else{
			log__printf(NULL, MOSQ_LOG_WARNING, "Information : Start connection with bridge %s.",
					config.bridges[config.bridge_count-1].name);
			mux_epoll__add_in(db, db->bridges[db->bridge_count-1]);
		}
	}else if(strncmp("$SYS/broker/bridge/del", topic,22)==0){
		rc = bridge__dynamic_parse_payload_del_json(payload,db,index);
		if(rc != 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to parse PUBLISH for bridge dynamic.");
			mosquitto__free(index);
			return MOSQ_ERR_BRIDGE_DYNA;
		}

		if(*index == -1){
			log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Unknow bridge name.");
			mosquitto__free(index);
			return MOSQ_ERR_BRIDGE_DYNA;
		}

		if(bridge__del(db, *index)){
			log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Unable to remove bridge %s.",
					config.bridges[*index].name);
			mosquitto__free(index);
			return MOSQ_ERR_BRIDGE_DYNA;
		}
	}

	mosquitto__free(index);
	return 0;
}

int bridge__dynamic_parse_payload_new_json(struct mosquitto_db *db, void* payload, struct mosquitto__config *config)
{
	int i;
	int len;
	struct mosquitto__bridge *cur_bridge = NULL;
	struct mosquitto__bridge_topic *cur_topic;

#ifndef WITH_CJSON
  return bridge__dynamic_parse_payload_new(db, payload, config);
#endif

	cJSON *message_json = cJSON_Parse(payload);
	if(message_json == NULL){
		const char *error_ptr = cJSON_GetErrorPtr();
		if(error_ptr != NULL){
			log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Unable to parse JSON Message for bridge dynamic. Maybe normal message configuration. %s", error_ptr);
		}
		cJSON_Delete(message_json);
		return bridge__dynamic_parse_payload_new(db, payload, config);
	}

  const cJSON *bridges_json = NULL;
	const cJSON *addresses_json = NULL;
	int bridges_count_json = 0;
	int addresses_count_json = 0;

  bridges_json = cJSON_GetObjectItemCaseSensitive(message_json, "bridges");
	if(!cJSON_IsArray(bridges_json)) {
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
		cJSON_Delete(message_json);
		return MOSQ_ERR_INVAL;
	}
  bridges_count_json = cJSON_GetArraySize(bridges_json);
	log__printf(NULL, MOSQ_LOG_DEBUG, "Information : %d bridge(s) dynamic.", bridges_count_json);
	if(bridges_count_json == 0){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: None Bridge in configuration.");
		cJSON_Delete(message_json);
		return MOSQ_ERR_INVAL;
	}
  const cJSON *bridge_json = NULL;
	// Actually, just one bridge defined in configuration bridges. Work in progress...
	int index = 0;
	bridge_json = cJSON_GetArrayItem(bridges_json, index);

	const cJSON *connection_json = NULL;
	const cJSON *topic_json = NULL;
	const cJSON *direction_json = NULL;
	const cJSON *qos_json= NULL;
	const cJSON *local_prefix_json = NULL;
	const cJSON *remote_prefix_json = NULL;

	connection_json = cJSON_GetObjectItemCaseSensitive(bridge_json, "connection");
	if(cJSON_IsString(connection_json) && (connection_json->valuestring != NULL)) {
		/* Check for existing bridge name. */
		for(i=0; i<db->bridge_count; i++){
			if(!strcmp(db->bridges[i]->bridge->name, connection_json->valuestring)){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Duplicate bridge name \"%s\".", connection_json->valuestring);
				cJSON_Delete(message_json);
				return MOSQ_ERR_INVAL;
			}
		}
		config->bridge_count++;
		config->bridges = mosquitto__realloc(config->bridges, config->bridge_count*sizeof(struct mosquitto__bridge));
		if(!config->bridges){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			cJSON_Delete(message_json);
			return MOSQ_ERR_NOMEM;
		}
		cur_bridge = &(config->bridges[config->bridge_count-1]);
		memset(cur_bridge, 0, sizeof(struct mosquitto__bridge));
		cur_bridge->name = mosquitto__strdup(connection_json->valuestring);
		if(!cur_bridge->name){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			cJSON_Delete(message_json);
			return MOSQ_ERR_NOMEM;
		}
		cur_bridge->keepalive = 60;
		cur_bridge->notifications = true;
		cur_bridge->notifications_local_only = false;
		cur_bridge->start_type = bst_automatic;
		cur_bridge->idle_timeout = 60;
		cur_bridge->restart_timeout = 0;
		cur_bridge->backoff_base = 5;
		cur_bridge->backoff_cap = 30;
		cur_bridge->threshold = 10;
		cur_bridge->try_private = true;
		cur_bridge->attempt_unsubscribe = true;
		cur_bridge->protocol_version = mosq_p_mqtt311;
		cur_bridge->primary_retry_sock = INVALID_SOCKET;
	}

	addresses_json = cJSON_GetObjectItemCaseSensitive(bridge_json, "addresses");
	if(!cJSON_IsArray(addresses_json)) {
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration (addresses).");
		cJSON_Delete(message_json);
		return MOSQ_ERR_INVAL;
	}
	addresses_count_json = cJSON_GetArraySize(addresses_json);
	if(addresses_count_json == 0){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: None address in bridge configuration.");
		cJSON_Delete(message_json);
		return MOSQ_ERR_INVAL;
	}
	const cJSON *addressItem_json = NULL;
	cJSON_ArrayForEach(addressItem_json, addresses_json) {
	  cJSON *address_json = cJSON_GetObjectItemCaseSensitive(addressItem_json, "address");
	  cJSON *port_json = cJSON_GetObjectItemCaseSensitive(addressItem_json, "port");

	  if(cJSON_IsString(address_json) && (address_json->valuestring != NULL)) {
	  	if(!cur_bridge || cur_bridge->addresses){
		  	log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
		  	cJSON_Delete(message_json);
				return MOSQ_ERR_INVAL;
		  }
		  cur_bridge->address_count++;
		  cur_bridge->addresses = mosquitto__realloc(cur_bridge->addresses, sizeof(struct bridge_address)*cur_bridge->address_count);
		  if(!cur_bridge->addresses){
		  	log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		  	cJSON_Delete(message_json);
				return MOSQ_ERR_NOMEM;
		  }
		  cur_bridge->addresses[cur_bridge->address_count-1].address = mosquitto__strdup(address_json->valuestring);
  	}

	  if(cJSON_IsNumber(port_json)){
		  if(port_json->valueint < 1 || port_json->valueint > 65535){
		  	log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid port value (%d).", port_json->valueint);
		  	cJSON_Delete(message_json);
				return MOSQ_ERR_INVAL;
	  	}
	  	cur_bridge->addresses[cur_bridge->address_count-1].port = port_json->valueint;
	  }
  }

	topic_json = cJSON_GetObjectItemCaseSensitive(bridge_json, "topic");
	if(cJSON_IsString(topic_json) && (topic_json->valuestring != NULL)) {
		cur_bridge->topic_count++;
		cur_bridge->topics = mosquitto__realloc(cur_bridge->topics,
				sizeof(struct mosquitto__bridge_topic)*cur_bridge->topic_count);
		if(!cur_bridge->topics){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			cJSON_Delete(message_json);
			return MOSQ_ERR_NOMEM;
		}
		cur_topic = &cur_bridge->topics[cur_bridge->topic_count-1];
		if(!strcmp(topic_json->valuestring, "\"\"")){
			cur_topic->topic = NULL;
		}else{
			cur_topic->topic = mosquitto__strdup(topic_json->valuestring);
			if(!cur_topic->topic){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				cJSON_Delete(message_json);
				return MOSQ_ERR_NOMEM;
			}
		}
		cur_topic->direction = bd_out;
		cur_topic->qos = 0;
		cur_topic->local_prefix = NULL;
		cur_topic->remote_prefix = NULL;
	}else{
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty topic value in configuration.");
		cJSON_Delete(message_json);
		return MOSQ_ERR_INVAL;
	}
	direction_json = cJSON_GetObjectItemCaseSensitive(bridge_json, "direction");
	if(cJSON_IsString(direction_json) && (direction_json->valuestring != NULL)) {
		if(!strcasecmp(direction_json->valuestring, "out")){
			cur_topic->direction = bd_out;
		}else if(!strcasecmp(direction_json->valuestring, "in")){
			cur_topic->direction = bd_in;
		}else if(!strcasecmp(direction_json->valuestring, "both")){
			cur_topic->direction = bd_both;
		}else{
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge topic direction '%s'.", direction_json->valuestring);
			cJSON_Delete(message_json);
			return MOSQ_ERR_INVAL;
		}
	}
	qos_json = cJSON_GetObjectItemCaseSensitive(bridge_json, "qos");
	if(cJSON_IsNumber(qos_json)){
		if(qos_json->valueint < 0 || qos_json->valueint > 2){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge QoS level '%d'.", qos_json->valueint);
			cJSON_Delete(message_json);
			return MOSQ_ERR_INVAL;
		}
		cur_topic->qos = qos_json->valueint;
	}
	local_prefix_json = cJSON_GetObjectItemCaseSensitive(bridge_json, "local_prefix");
	if(cJSON_IsString(local_prefix_json) && (local_prefix_json->valuestring != NULL)) {
		cur_bridge->topic_remapping = true;
		if(!strcmp(local_prefix_json->valuestring, "\"\"")){
			cur_topic->local_prefix = NULL;
		}else{
			if(mosquitto_pub_topic_check(local_prefix_json->valuestring) != MOSQ_ERR_SUCCESS){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge topic local prefix '%s'.", local_prefix_json->valuestring);
				cJSON_Delete(message_json);
				return MOSQ_ERR_INVAL;
			}
			cur_topic->local_prefix = mosquitto__strdup(local_prefix_json->valuestring);
			if(!cur_topic->local_prefix){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				cJSON_Delete(message_json);
				return MOSQ_ERR_NOMEM;
			}
		}
	}
	remote_prefix_json = cJSON_GetObjectItemCaseSensitive(bridge_json, "remote_prefix");
	if(cJSON_IsString(remote_prefix_json) && (remote_prefix_json->valuestring != NULL)) {
		if(!strcmp(remote_prefix_json->valuestring, "\"\"")){
			cur_topic->remote_prefix = NULL;
		}else{
			if(mosquitto_pub_topic_check(remote_prefix_json->valuestring) != MOSQ_ERR_SUCCESS){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge topic remote prefix '%s'.", remote_prefix_json->valuestring);
				cJSON_Delete(message_json);
				return MOSQ_ERR_INVAL;
			}
			cur_topic->remote_prefix = mosquitto__strdup(remote_prefix_json->valuestring);
			if(!cur_topic->remote_prefix){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				cJSON_Delete(message_json);
				return MOSQ_ERR_NOMEM;
			}
		}
	}

  //Last verification
	if(cur_bridge->address_count == 0){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty address value in configuration.");
		cJSON_Delete(message_json);
		return MOSQ_ERR_INVAL;
	}
	if(config->bridge_count == 0){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty connection value in configuration.");
		cJSON_Delete(message_json);
		return MOSQ_ERR_INVAL;
	}
	if(cur_topic->topic == NULL &&
			(cur_topic->local_prefix == NULL || cur_topic->remote_prefix == NULL)){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge remapping.");
		cJSON_Delete(message_json);
		return MOSQ_ERR_INVAL;
	}

	if(cur_topic->local_prefix){
		if(cur_topic->topic){
			len = strlen(cur_topic->topic) + strlen(cur_topic->local_prefix)+1;
			cur_topic->local_topic = mosquitto__malloc(len+1);
			if(!cur_topic->local_topic){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				cJSON_Delete(message_json);
				return MOSQ_ERR_NOMEM;
			}
			snprintf(cur_topic->local_topic, len+1, "%s%s", cur_topic->local_prefix, cur_topic->topic);
			cur_topic->local_topic[len] = '\0';
		}else{
			cur_topic->local_topic = mosquitto__strdup(cur_topic->local_prefix);
			if(!cur_topic->local_topic){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				cJSON_Delete(message_json);
				return MOSQ_ERR_NOMEM;
			}
		}
	}else{
		cur_topic->local_topic = mosquitto__strdup(cur_topic->topic);
		if(!cur_topic->local_topic){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			cJSON_Delete(message_json);
			return MOSQ_ERR_NOMEM;
		}
	}

	if(cur_topic->remote_prefix){
		if(cur_topic->topic){
			len = strlen(cur_topic->topic) + strlen(cur_topic->remote_prefix)+1;
			cur_topic->remote_topic = mosquitto__malloc(len+1);
			if(!cur_topic->remote_topic){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				cJSON_Delete(message_json);
				return MOSQ_ERR_NOMEM;
			}
			snprintf(cur_topic->remote_topic, len, "%s%s", cur_topic->remote_prefix, cur_topic->topic);
			cur_topic->remote_topic[len] = '\0';
		}else{
			cur_topic->remote_topic = mosquitto__strdup(cur_topic->remote_prefix);
			if(!cur_topic->remote_topic){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				cJSON_Delete(message_json);
				return MOSQ_ERR_NOMEM;
			}
		}
	}else{
		cur_topic->remote_topic = mosquitto__strdup(cur_topic->topic);
		if(!cur_topic->remote_topic){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			cJSON_Delete(message_json);
			return MOSQ_ERR_NOMEM;
		}
	}
  cJSON_Delete(message_json);
  return MOSQ_ERR_SUCCESS;
}

int bridge__dynamic_parse_payload_new(struct mosquitto_db *db, void* payload, struct mosquitto__config *config)
{
	char *buf = NULL;
	char *token;
	int tmp_int;
	char *saveptr = NULL;
	struct mosquitto__bridge *cur_bridge = NULL;
	struct mosquitto__bridge_topic *cur_topic;

	char *address;
	int i;
	int len;
	int nb_param = 0;

	buf = strtok(payload, "\n");

	while(buf) {
	   	if(buf[0] != '#' && buf[0] != 10 && buf[0] != 13){
			while(buf[strlen(buf)-1] == 10 || buf[strlen(buf)-1] == 13){
				buf[strlen(buf)-1] = 0;
			}
			token = strtok_r(buf, " ", &saveptr);

			if(token)
			{
				if(!strcmp(token, "address") || !strcmp(token, "addresses"))
				{
					nb_param ++;
					if(!cur_bridge || cur_bridge->addresses){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					while((token = strtok_r(NULL, " ", &saveptr))){
						cur_bridge->address_count++;
						cur_bridge->addresses = mosquitto__realloc(cur_bridge->addresses, sizeof(struct bridge_address)*cur_bridge->address_count);
						if(!cur_bridge->addresses){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
						cur_bridge->addresses[cur_bridge->address_count-1].address = token;
					}
					for(i=0; i<cur_bridge->address_count; i++){
						address = strtok_r(cur_bridge->addresses[i].address, ":", &saveptr);
						if(address){
							token = strtok_r(NULL, ":", &saveptr);
							if(token){
								tmp_int = atoi(token);
								if(tmp_int < 1 || tmp_int > 65535){
									log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid port value (%d).", tmp_int);
									return MOSQ_ERR_INVAL;
								}
								cur_bridge->addresses[i].port = tmp_int;
							}else{
								cur_bridge->addresses[i].port = 1883;
							}
							cur_bridge->addresses[i].address = mosquitto__strdup(address);
							//_conf_attempt_resolve(address, "bridge address", MOSQ_LOG_WARNING, "Warning");
						}
					}
					if(cur_bridge->address_count == 0){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty address value in configuration.");
						return MOSQ_ERR_INVAL;
					}
				}
				else if(!strcmp(token, "connection"))
				{
					nb_param ++;
					//if(reload) continue; // FIXME
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						/* Check for existing bridge name. */
						for(i=0; i<db->bridge_count; i++){
							if(!strcmp(db->bridges[i]->bridge->name, token)){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Duplicate bridge name \"%s\".", token);
								return MOSQ_ERR_INVAL;
							}
						}

						config->bridge_count++;
						config->bridges = mosquitto__realloc(config->bridges, config->bridge_count*sizeof(struct mosquitto__bridge));
						if(!config->bridges){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
						cur_bridge = &(config->bridges[config->bridge_count-1]);
						memset(cur_bridge, 0, sizeof(struct mosquitto__bridge));
						cur_bridge->name = mosquitto__strdup(token);
						if(!cur_bridge->name){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
						cur_bridge->keepalive = 60;
						cur_bridge->notifications = true;
						cur_bridge->notifications_local_only = false;
						cur_bridge->start_type = bst_automatic;
						cur_bridge->idle_timeout = 60;
						cur_bridge->restart_timeout = 0;
						cur_bridge->backoff_base = 5;
						cur_bridge->backoff_cap = 30;
						cur_bridge->threshold = 10;
						cur_bridge->try_private = true;
						cur_bridge->attempt_unsubscribe = true;
						cur_bridge->protocol_version = mosq_p_mqtt311;
						cur_bridge->primary_retry_sock = INVALID_SOCKET;
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty connection value in configuration.");
						return MOSQ_ERR_INVAL;
					}
				}
				else if(!strcmp(token, "topic"))
				{
					nb_param ++;
					if(!cur_bridge){
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge configuration.");
						return MOSQ_ERR_INVAL;
					}
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						cur_bridge->topic_count++;
						cur_bridge->topics = mosquitto__realloc(cur_bridge->topics,
								sizeof(struct mosquitto__bridge_topic)*cur_bridge->topic_count);
						if(!cur_bridge->topics){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
						cur_topic = &cur_bridge->topics[cur_bridge->topic_count-1];
						if(!strcmp(token, "\"\"")){
							cur_topic->topic = NULL;
						}else{
							cur_topic->topic = mosquitto__strdup(token);
							if(!cur_topic->topic){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
								return MOSQ_ERR_NOMEM;
							}
						}
						cur_topic->direction = bd_out;
						cur_topic->qos = 0;
						cur_topic->local_prefix = NULL;
						cur_topic->remote_prefix = NULL;
					}else{
						log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty topic value in configuration.");
						return MOSQ_ERR_INVAL;
					}
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						if(!strcasecmp(token, "out")){
							cur_topic->direction = bd_out;
						}else if(!strcasecmp(token, "in")){
							cur_topic->direction = bd_in;
						}else if(!strcasecmp(token, "both")){
							cur_topic->direction = bd_both;
						}else{
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge topic direction '%s'.", token);
							return MOSQ_ERR_INVAL;
						}
						token = strtok_r(NULL, " ", &saveptr);
						if(token){
							cur_topic->qos = atoi(token);
							if(cur_topic->qos < 0 || cur_topic->qos > 2){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge QoS level '%s'.", token);
								return MOSQ_ERR_INVAL;
							}

							token = strtok_r(NULL, " ", &saveptr);
							if(token){
								cur_bridge->topic_remapping = true;
								if(!strcmp(token, "\"\"")){
									cur_topic->local_prefix = NULL;
								}else{
									if(mosquitto_pub_topic_check(token) != MOSQ_ERR_SUCCESS){
										log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge topic local prefix '%s'.", token);
										return MOSQ_ERR_INVAL;
									}
									cur_topic->local_prefix = mosquitto__strdup(token);
									if(!cur_topic->local_prefix){
										log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
										return MOSQ_ERR_NOMEM;
									}
								}

								token = strtok_r(NULL, " ", &saveptr);
								if(token){
									if(!strcmp(token, "\"\"")){
										cur_topic->remote_prefix = NULL;
									}else{
										if(mosquitto_pub_topic_check(token) != MOSQ_ERR_SUCCESS){
											log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge topic remote prefix '%s'.", token);
											return MOSQ_ERR_INVAL;
										}
										cur_topic->remote_prefix = mosquitto__strdup(token);
										if(!cur_topic->remote_prefix){
											log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
											return MOSQ_ERR_NOMEM;
										}
									}
								}
							}
						}
					}
					if(cur_topic->topic == NULL &&
							(cur_topic->local_prefix == NULL || cur_topic->remote_prefix == NULL)){

						log__printf(NULL, MOSQ_LOG_ERR, "Error: Invalid bridge remapping.");
						return MOSQ_ERR_INVAL;
					}
					if(cur_topic->local_prefix){
						if(cur_topic->topic){
							len = strlen(cur_topic->topic) + strlen(cur_topic->local_prefix)+1;
							cur_topic->local_topic = mosquitto__malloc(len+1);
							if(!cur_topic->local_topic){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
								return MOSQ_ERR_NOMEM;
							}
							snprintf(cur_topic->local_topic, len+1, "%s%s", cur_topic->local_prefix, cur_topic->topic);
							cur_topic->local_topic[len] = '\0';
						}else{
							cur_topic->local_topic = mosquitto__strdup(cur_topic->local_prefix);
							if(!cur_topic->local_topic){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
								return MOSQ_ERR_NOMEM;
							}
						}
					}else{
						cur_topic->local_topic = mosquitto__strdup(cur_topic->topic);
						if(!cur_topic->local_topic){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
					}

					if(cur_topic->remote_prefix){
						if(cur_topic->topic){
							len = strlen(cur_topic->topic) + strlen(cur_topic->remote_prefix)+1;
							cur_topic->remote_topic = mosquitto__malloc(len+1);
							if(!cur_topic->remote_topic){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
								return MOSQ_ERR_NOMEM;
							}
							snprintf(cur_topic->remote_topic, len, "%s%s", cur_topic->remote_prefix, cur_topic->topic);
							cur_topic->remote_topic[len] = '\0';
						}else{
							cur_topic->remote_topic = mosquitto__strdup(cur_topic->remote_prefix);
							if(!cur_topic->remote_topic){
								log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
								return MOSQ_ERR_NOMEM;
							}
						}
					}else{
						cur_topic->remote_topic = mosquitto__strdup(cur_topic->topic);
						if(!cur_topic->remote_topic){
							log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
					}
				}
			}
		}
		buf  = strtok(NULL, "\n");
	}

	if(nb_param>=3){
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_INVAL;
	}
}

int bridge__dynamic_parse_payload_del_json(void* payload, struct mosquitto_db *db, int *index)
{
	int i;

#ifndef WITH_CJSON
  return bridge__dynamic_parse_payload_del(payload,db,index);
#endif

	cJSON *message_json = cJSON_Parse(payload);
	if(message_json == NULL){
		const char *error_ptr = cJSON_GetErrorPtr();
		if(error_ptr != NULL){
			log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Unable to parse JSON Message for bridge dynamic. Maybe normal message configuration. %s", error_ptr);
		}
		cJSON_Delete(message_json);
		return bridge__dynamic_parse_payload_del(payload,db,index);
	}

	const cJSON *connection_json = NULL;
	connection_json = cJSON_GetObjectItemCaseSensitive(message_json, "connection");
	if(cJSON_IsString(connection_json) && (connection_json->valuestring != NULL)) {
			/* Check for existing bridge name. */
			for(i=0; i<db->bridge_count; i++){
				if(!strcmp(db->bridges[i]->bridge->name, connection_json->valuestring)){
					*index = i;
				}
			}
		}else{
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty connection value in configuration.");
			return MOSQ_ERR_INVAL;
		}

		return MOSQ_ERR_SUCCESS;
}

int bridge__dynamic_parse_payload_del(void* payload, struct mosquitto_db *db, int *index)
{
	char *buf;
	char *token;
	char *saveptr = NULL;
	int i;

	buf = strdup(payload);
   	if(buf[0] != '#' && buf[0] != 10 && buf[0] != 13){
		while(buf[strlen(buf)-1] == 10 || buf[strlen(buf)-1] == 13){
			buf[strlen(buf)-1] = 0;
		}
		token = strtok_r(buf, " ", &saveptr);

		if(token)
		{
			if(!strcmp(token, "connection"))
			{
				//if(reload) continue; // FIXME
				token = strtok_r(NULL, " ", &saveptr);
				if(token){
					/* Check for existing bridge name. */
					for(i=0; i<db->bridge_count; i++){
						if(!strcmp(db->bridges[i]->bridge->name, token)){
							*index = i;
						}
					}
				}else{
					log__printf(NULL, MOSQ_LOG_ERR, "Error: Empty connection value in configuration.");
					return MOSQ_ERR_INVAL;
				}
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
}

static int config__check(struct mosquitto__config *config)
{
	/* Checks that are easy to make after the config has been loaded. */

#ifdef WITH_BRIDGE
	int i, j;
	struct mosquitto__bridge *bridge1, *bridge2;
	char hostname[256];
	int len;

	/* Check for bridge duplicate local_clientid, need to generate missing IDs
	 * first. */
	for(i=0; i<config->bridge_count; i++){
		bridge1 = &config->bridges[i];

		if(!bridge1->remote_clientid){
			if(!gethostname(hostname, 256)){
				len = strlen(hostname) + strlen(bridge1->name) + 2;
				bridge1->remote_clientid = mosquitto__malloc(len);
				if(!bridge1->remote_clientid){
					return MOSQ_ERR_NOMEM;
				}
				snprintf(bridge1->remote_clientid, len, "%s.%s", hostname, bridge1->name);
			}else{
				return 1;
			}
		}

		if(!bridge1->local_clientid){
			len = strlen(bridge1->remote_clientid) + strlen("local.") + 2;
			bridge1->local_clientid = mosquitto__malloc(len);
			if(!bridge1->local_clientid){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				return MOSQ_ERR_NOMEM;
			}
			snprintf(bridge1->local_clientid, len, "local.%s", bridge1->remote_clientid);
		}
	}

	for(i=0; i<config->bridge_count; i++){
		bridge1 = &config->bridges[i];
		for(j=i+1; j<config->bridge_count; j++){
			bridge2 = &config->bridges[j];
			if(!strcmp(bridge1->local_clientid, bridge2->local_clientid)){
				log__printf(NULL, MOSQ_LOG_ERR, "Error: Bridge local_clientid "
						"'%s' is not unique. Try changing or setting the "
						"local_clientid value for one of the bridges.",
						bridge1->local_clientid);
				return MOSQ_ERR_INVAL;
			}
		}
	}
#endif
	return MOSQ_ERR_SUCCESS;
}
