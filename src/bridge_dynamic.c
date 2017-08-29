/*
Copyright (c) 2017 Tifaifai Maupiti <tifaifai.maupiti@gmail.com>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

Contributor:
   Tifaifai Maupiti - Initial implementation and documentation.
*/

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "mqtt3_protocol.h"
#include "memory_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "util_mosq.h"

int bridge__dynamic_analyse(struct mosquitto_db *db, char *topic, void* payload, uint32_t payloadlen)
{
	int rc;
	int *index;

	struct mosquitto__config config;
	config__init(&config);

	index = (int*) malloc(sizeof(int));
	*index = -1;

	if(strncmp("$SYS/broker/bridge/new",topic,22)==0){
		rc = bridge__dynamic_parse_payload_new(db, payload, &config);
		if(rc != 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to parse PUBLISH.");
			return rc;
		}

		if(bridge__new(db, &(config.bridges[config.bridge_count-1]))){
			log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Unable to connect to bridge %s.",
					config.bridges[config.bridge_count-1].name);
		}
	}else if(strncmp("$SYS/broker/bridge/del", topic,22)==0){
		rc = bridge__dynamic_parse_payload_del(payload,db,index);
		if(rc != 0){
			log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to parse PUBLISH.");
			return rc;
		}

		if(*index == -1){
			log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Unknow bridge name.");
			return 0;
		}

		if(bridge__del(db, *index)){
			log__printf(NULL, MOSQ_LOG_WARNING, "Warning: Unable to remove bridge %s.",
					config.bridges[*index].name);
		}
	}

	free(index);

	return 0;
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
						cur_bridge->start_type = bst_automatic;
						cur_bridge->idle_timeout = 60;
						cur_bridge->restart_timeout = 30;
						cur_bridge->threshold = 10;
						cur_bridge->try_private = true;
						cur_bridge->attempt_unsubscribe = true;
						cur_bridge->protocol_version = mosq_p_mqtt31;
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
		return 0;
	}else{
		return MOSQ_ERR_INVAL;
	}
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

	return 0;
}
