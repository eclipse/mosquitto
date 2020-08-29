/*
Copyright (c) 2015-2020 Tifaifai Maupiti <tifaifai.maupiti@gmail.com>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
Tifaifai Maupiti - initial implementation and documentation.
*/
#include "config.h"

#ifdef WITH_CJSON
#  include <cjson/cJSON.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#else
#include <process.h>
#include <winsock2.h>
#define snprintf sprintf_s
#endif

#include <mqtt_protocol.h>
#include <mosquitto.h>
#include "client_shared.h"
#include "pub_shared.h"

/* Global variables for use in callbacks. See sub_client.c for an example of
 * using a struct to hold variables for use in callbacks. */
struct mosquitto *mosq = NULL;
bool process_messages = true;

static int last_mid_sent = -1;
static bool disconnect_sent = false;
static int publish_count = 0;
static volatile int status = STATUS_CONNECTING;

static char *topic = NULL;
static char *name = NULL;
static char *pattern = NULL;
static char *direction = NULL;
static char *local_prefix = NULL;
static char *remote_prefix = NULL;
static char *remote_add = NULL;
static int remote_port;
static int qos = 0;
static char *msg = NULL;
static char *msg_json = NULL;

void * ptrMosq = NULL;
int process_run = 1;
int nb_line = 0;

struct bridge{
  char *name;
};

struct bridge_list{
  int bridge_list_count;
  struct bridge* bridge;
};

struct bridge_list *bridges = NULL;

int show_bridges(struct bridge_list* bridges)
{
  int i;
  char * bridge_name;
  int bridge_name_len;

  for(i=0; i<nb_line ;i++)
  {
    printf("\33[2K");
    printf("\033[A");
  }

  nb_line = 0;

  for(i=0;i<bridges->bridge_list_count;i++)
  {
    bridge_name_len = strlen(bridges->bridge[i].name) - strlen("/state") - strlen("$SYS/broker/connection/");
    bridge_name = malloc(bridge_name_len*sizeof(char));
    memset(bridge_name, 0, bridge_name_len);
    memcpy(bridge_name, bridges->bridge[i].name + strlen("$SYS/broker/connection/")*sizeof(char) , bridge_name_len);
    printf("%s\n",bridge_name);
    fflush(stdout);
    free(bridge_name);
    nb_line++;
  }
  return MOSQ_ERR_SUCCESS;
}

int show_bridges_json(struct bridge_list* bridges){
  int rc;

  #ifndef WITH_CJSON
    rc = show_bridges(bridges);
    return rc;
  #endif

  int i;
  char * bridge_name;
  int bridge_name_len;
  char *string_json = NULL;
  cJSON *bridges_json = NULL;
  cJSON *bridge_json = NULL;
  cJSON *connection_json = NULL;

  if(cfg.bridge_conf_json == CONF_JSON){
    cJSON *s_bridges_json = cJSON_CreateObject();
    if(s_bridges_json == NULL) {
      cJSON_Delete(s_bridges_json);
      return MOSQ_ERR_INVAL;
    }
    bridges_json = cJSON_CreateArray();
    if(bridges_json == NULL) {
      cJSON_Delete(s_bridges_json);
      return MOSQ_ERR_INVAL;
    }
    cJSON_AddItemToObject(s_bridges_json, "bridges", bridges_json);
    for(i=0;i<bridges->bridge_list_count;i++)
    {
      bridge_json = cJSON_CreateObject();
      if(bridge_json == NULL){
        cJSON_Delete(s_bridges_json);
        return MOSQ_ERR_INVAL;
      }
      cJSON_AddItemToArray(bridges_json, bridge_json);
      bridge_name_len = strlen(bridges->bridge[i].name) - strlen("/state") - strlen("$SYS/broker/connection/");
      bridge_name = malloc(bridge_name_len*sizeof(char));
      memset(bridge_name, 0, bridge_name_len);
      memcpy(bridge_name, bridges->bridge[i].name + strlen("$SYS/broker/connection/")*sizeof(char) , bridge_name_len);
      connection_json = cJSON_CreateString(bridge_name);
      if(connection_json == NULL){
        cJSON_Delete(s_bridges_json);
        return MOSQ_ERR_INVAL;
      }
      cJSON_AddItemToObject(bridge_json, "connection", connection_json);
      free(bridge_name);
    }
    string_json = cJSON_PrintUnformatted(s_bridges_json);
    if(string_json == NULL){
      printf("Error, Failed to print show_bridges.\n");
    }
    printf("%s\n",string_json);
    cJSON_Delete(s_bridges_json);
    return MOSQ_ERR_SUCCESS;
  }else{
    rc = show_bridges(bridges);
    return rc;
  }
  return MOSQ_ERR_SUCCESS;
}

void my_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message, const mosquitto_property *properties)
{
  UNUSED(properties);
  int rc = 0;
  struct bridge_list *bridges;
  bridges = (struct bridge_list*) obj;
  int valid_erase = 0;
  int i;

  if(!strcmp(message->payload,"1")){
      bridges->bridge_list_count++;
      bridges->bridge = realloc(bridges->bridge, sizeof(struct bridge)*bridges->bridge_list_count);
      if(!bridges->bridge){
        printf("Error: Out of memory. 1\n");
        exit(-1);
      }
      bridges->bridge[bridges->bridge_list_count-1].name = malloc(sizeof(char)*strlen(message->topic));
      if(!bridges->bridge[bridges->bridge_list_count-1].name){
        printf("Error: Out of memory. 2\n");
        exit(-1);
      }
      bridges->bridge[bridges->bridge_list_count-1].name = strdup(message->topic);
      rc = show_bridges_json(bridges);
    }else{
      if(bridges->bridge_list_count>0){
        for (i = 0; i < bridges->bridge_list_count; i++) {
          if(!strcmp(bridges->bridge[i].name,message->topic)){
            valid_erase = i;
            bridges->bridge_list_count--;
          }
        }

        if(valid_erase){
          for (i = valid_erase; i < bridges->bridge_list_count; i++) {
            bridges->bridge[i] = bridges->bridge[i+1];
          }
          bridges->bridge = realloc(bridges->bridge, sizeof(struct bridge)*bridges->bridge_list_count);
          if(!bridges->bridge){
            printf("Error: Out of memory. 3\n");
            exit(-1);
          }
          rc = show_bridges_json(bridges);
        }
      }else{
        bridges->bridge_list_count = 0;
      }
    }
}

void my_disconnect_callback(struct mosquitto *mosq, void *obj, int rc, const mosquitto_property *properties)
{
	UNUSED(mosq);
	UNUSED(obj);
	UNUSED(rc);
	UNUSED(properties);

	if(rc == 0){
		status = STATUS_DISCONNECTED;
	}
}

int my_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, void *payload, int qos, bool retain)
{
  return mosquitto_publish_v5(mosq, mid, topic, payloadlen, payload, qos, retain, cfg.publish_props);
}

void my_connect_callback_pub(struct mosquitto *mosq, void *obj, int result, int flags, const mosquitto_property *properties)
{
	UNUSED(obj);
	UNUSED(flags);
	UNUSED(properties);
  int rc = MOSQ_ERR_SUCCESS;

	if(!result){
		rc = my_publish(mosq, &mid_sent, cfg.topic, cfg.msglen, cfg.message, cfg.qos, cfg.retain);
		if(rc){
			switch(rc){
				case MOSQ_ERR_INVAL:
					err_printf(&cfg, "Error: Invalid input. Does your topic contain '+' or '#'?\n");
					break;
				case MOSQ_ERR_NOMEM:
					err_printf(&cfg, "Error: Out of memory when trying to publish message.\n");
					break;
				case MOSQ_ERR_NO_CONN:
					err_printf(&cfg, "Error: Client not connected when trying to publish.\n");
					break;
				case MOSQ_ERR_PROTOCOL:
					err_printf(&cfg, "Error: Protocol error when communicating with broker.\n");
					break;
				case MOSQ_ERR_PAYLOAD_SIZE:
					err_printf(&cfg, "Error: Message payload is too large.\n");
					break;
				case MOSQ_ERR_QOS_NOT_SUPPORTED:
					err_printf(&cfg, "Error: Message QoS not supported on broker, try a lower QoS.\n");
					break;
			}
			mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
		}
	}else{
		if(result){
			if(cfg.protocol_version == MQTT_PROTOCOL_V5){
				if(result == MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION){
					err_printf(&cfg, "Connection error: %s. Try connecting to an MQTT v5 broker, or use MQTT v3.x mode.\n", mosquitto_reason_string(result));
				}else{
					err_printf(&cfg, "Connection error: %s\n", mosquitto_reason_string(result));
				}
			}else{
				err_printf(&cfg, "Connection error: %s\n", mosquitto_connack_string(result));
			}
			mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
		}
	}
}

void my_publish_callback(struct mosquitto *mosq, void *obj, int mid, int reason_code, const mosquitto_property *properties)
{
	UNUSED(obj);
	UNUSED(properties);

	last_mid_sent = mid;
	if(reason_code > 127){
		err_printf(&cfg, "Warning: Publish %d failed: %s.\n", mid, mosquitto_reason_string(reason_code));
	}
	publish_count++;
  if(disconnect_sent == false){
		mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
		disconnect_sent = true;
	}
}

void my_connect_callback_sub(struct mosquitto *mosq, void *obj, int result, int flags, const mosquitto_property *properties)
{
	UNUSED(obj);
	UNUSED(flags);
	UNUSED(properties);

	if(!result){
    mosquitto_subscribe(mosq, NULL, "$SYS/broker/connection/#", 0);
  }
}

void my_subscribe_callback(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
  UNUSED(obj);
  int i;

	if(cfg.debug){
		if(!cfg.quiet) printf("Subscribed (mid: %d): %d", mid, granted_qos[0]);
		for(i=1; i<qos_count; i++){
			if(!cfg.quiet) printf(", %d", granted_qos[i]);
		}
		if(!cfg.quiet) printf("\n");
	}

	if(cfg.exit_after_sub){
		mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
	}
}

int bridge_shared_init(void)
{
  bridges = malloc(sizeof(struct bridge_list));
  if(!bridges){
    printf("Error: Out of memory.\n");
    return 1;
  }
  bridges->bridge_list_count = 0;
  ptrMosq = bridges;
	return 0;
}

int pub_loop(struct mosquitto *mosq)
{
	int rc;
	int loop_delay = 1000;

	do{
		rc = mosquitto_loop(mosq, loop_delay, 1);
	}while(rc == MOSQ_ERR_SUCCESS);

	if(status == STATUS_DISCONNECTED){
		return MOSQ_ERR_SUCCESS;
	}else{
		return rc;
	}
}

void bridge_shared_cleanup(void)
{
	free(bridges);
}

void print_usage(void)
{
    int major, minor, revision;

    mosquitto_lib_version(&major, &minor, &revision);
    printf("mosquitto_bridger is a simple mqtt client that will publish a message on a single topic on one broker to manage bridge dynamiclly with another and exit.\n");
    printf("mosquitto_bridge version %s running on libmosquitto %d.%d.%d.\n\n", VERSION, major, minor, revision);
    printf("Usage: mosquitto_bridge [-h local host] [-p local port] [-q qos] -a remote host -P remote port -t bridge pattern -D bridge direction -l local prefix -r remote prefix\n");
    printf("\n");
    printf("mosquitto_bridge --help\n\n");
    printf(" -j | --json        : JSON message configuration\n");
    printf(" -a | --address     : address configuration\n");
    printf(" -c | --connection  : connection configuration\n");
    printf(" -d | --del         : delete bridge dynamic\n");
    printf(" -D | --direction   : direction configuration : in, out or both\n");
    printf(" -h | --host        : local Mosquitto host bridge dynamic compatible broker to make new/del bridge.\n");
    printf(" -k | --know        : know actif bridges on local broker\n");
    printf(" -l | --local       : local prefix configuration\n");
    printf(" -n | --new         : new bridge dynamic\n");
    printf(" -p | --port        : network port to connect to local. Defaults to 1883.\n");
    printf(" -P | --pw          : provide a password (requires MQTT 3.1 broker)\n");
    printf(" -q | --qos         : quality of service level to use for all messages. Defaults to 0.\n");
    printf(" -r | --remote      : remote prefix configuration\n");
    printf(" -R | --remotePort  : network port to connect to remote. no defaults\n");
    printf(" -u | --username    : provide a username (requires MQTT 3.1 broker)\n");
    printf(" --help             : display this message.\n");
}

#ifndef WIN32
void my_signal_handler(int signum)
{
	if(signum == SIGALRM || signum == SIGTERM || signum == SIGINT){
    process_run = 0;
	}
}
#endif

int main(int argc, char *argv[])
{
	int rc;
  #ifndef WIN32
  		struct sigaction sigact;
  #endif
	int msg_len, msg_json_len;

	mosquitto_lib_init();

	rc = client_config_load_bridge(&cfg, CLIENT_PUB, argc, argv);
	if(rc){
		if(rc == 2){
			/* --help */
			print_usage();
		}else{
			fprintf(stderr, "\nUse 'mosquitto_bridge(2) --help' to see usage.\n");
		}
		goto cleanup;
	}

  if(cfg.know_bridge_connection){
    if(bridge_shared_init()) goto cleanup;
  }
	if(cfg.bridgeType == BRIDGE_NEW){
			topic = strdup("$SYS/broker/bridge/new");
			name = cfg.bridge.name;
			pattern = cfg.bridge.topics[0].topic;
			qos = cfg.bridge.topics[0].qos;
			if(cfg.bridge.topics[0].direction == bd_out){
					direction = strdup("out");
			}else if(cfg.bridge.topics[0].direction == bd_in){
					direction = strdup("in");
			}else if(cfg.bridge.topics[0].direction == bd_both){
					direction = strdup("both");
			}
			local_prefix = cfg.bridge.topics[0].local_prefix;
			remote_prefix = cfg.bridge.topics[0].remote_prefix;
			remote_add  = cfg.bridge.addresses[0].address;
			remote_port = cfg.bridge.addresses[0].port;
      if(cfg.bridge_conf_json == CONF_JSON){
        msg_json_len = snprintf(NULL,0,"{\"bridges\":[{\"connection\":\"%s\",\"addresses\":[{\"address\":\"%s\",\"port\":%d}],\"topic\":\"%s\",\"direction\":\"%s\",\"qos\":%d,\"local_prefix\":\"%s\",\"remote_prefix\":\"%s\"}]}",name
                                                        ,remote_add,remote_port,pattern,direction,qos,local_prefix,remote_prefix);
        msg_json_len++;
        msg_json = (char*) malloc(msg_json_len);
        snprintf(msg_json,msg_json_len,"{\"bridges\":[{\"connection\":\"%s\",\"addresses\":[{\"address\":\"%s\",\"port\":%d}],\"topic\":\"%s\",\"direction\":\"%s\",\"qos\":%d,\"local_prefix\":\"%s\",\"remote_prefix\":\"%s\"}]}",name
                                                        ,remote_add,remote_port,pattern,direction,qos,local_prefix,remote_prefix);
        cfg.message = strdup(msg_json);
        cfg.msglen = msg_json_len;
      }else{
			  msg_len = snprintf(NULL,0,"connection %s\naddress %s:%d\ntopic %s %s %d %s %s",name
																																	,remote_add
																																	,remote_port
																																	,pattern
																																	,direction
																																	,qos
																																	,local_prefix
																																	,remote_prefix);
			  msg_len++;
			  msg = (char*) malloc(msg_len);
			  snprintf(msg,msg_len,"connection %s\naddress %s:%d\ntopic %s %s %d %s %s",name
																																			,remote_add
																																			,remote_port
																																			,pattern
																																			,direction
																																			,qos
																																			,local_prefix
																																			,remote_prefix);
        cfg.message = strdup(msg);
        cfg.msglen = msg_len;
      }
      cfg.topic = strdup(topic);
			printf("Message New Bridge (%d):\n%s\n", cfg.msglen, cfg.message);
	}else if(cfg.bridgeType == BRIDGE_DEL){
			topic = strdup("$SYS/broker/bridge/del");
			name = cfg.bridge.name;
      if(cfg.bridge_conf_json == CONF_JSON){
        msg_json_len = snprintf(NULL,0,"{\"connection\":\"%s\"}", name);
        msg_json_len++;
        msg_json = (char*) malloc(msg_json_len);
        snprintf(msg_json,msg_json_len,"{\"connection\":\"%s\"}", name);
        cfg.message = strdup(msg_json);
        cfg.msglen = msg_json_len;
      }else{
        msg_len = snprintf(NULL,0,"connection %s",name);
        msg_len++;
        msg = (char*) malloc(msg_len);
        snprintf(msg,msg_len,"connection %s",name);
        cfg.message = strdup(msg);
        cfg.msglen = msg_len;
      }
      cfg.topic = strdup(topic);
			printf("Message Del Bridge (%d):\n%s\n", cfg.msglen, cfg.message);
	}

	if(client_id_generate(&cfg)){
		goto cleanup;
	}

	mosq = mosquitto_new(cfg.id, cfg.clean_session, ptrMosq);
	if(!mosq){
		switch(errno){
			case ENOMEM:
				err_printf(&cfg, "Error: Out of memory.\n");
				break;
			case EINVAL:
				err_printf(&cfg, "Error: Invalid id.\n");
				break;
		}
		goto cleanup;
	}

	mosquitto_disconnect_v5_callback_set(mosq, my_disconnect_callback);
  if(!cfg.know_bridge_connection){
    mosquitto_connect_v5_callback_set(mosq, my_connect_callback_pub);
    mosquitto_publish_v5_callback_set(mosq, my_publish_callback);
  }

	if(client_opts_set(mosq, &cfg)){
		goto cleanup;
	}

	rc = client_connect(mosq, &cfg);
	if(rc){
		goto cleanup;
	}

  #ifndef WIN32
  	sigact.sa_handler = my_signal_handler;
  	sigemptyset(&sigact.sa_mask);
  	sigact.sa_flags = 0;

  	if(sigaction(SIGALRM, &sigact, NULL) == -1){
  		perror("sigaction");
  		goto cleanup;
  	}

  	if(sigaction(SIGTERM, &sigact, NULL) == -1){
  		perror("sigaction");
  		goto cleanup;
  	}

  	if(sigaction(SIGINT, &sigact, NULL) == -1){
  		perror("sigaction");
  		goto cleanup;
  	}

  	if(cfg.timeout){
  		alarm(cfg.timeout);
  	}
  #endif

  if(cfg.know_bridge_connection){
    mosquitto_subscribe_callback_set(mosq,  my_subscribe_callback);
  	mosquitto_connect_v5_callback_set(mosq, my_connect_callback_sub);
  	mosquitto_message_v5_callback_set(mosq, my_message_callback);

    mosquitto_loop_start(mosq);
    while (process_run) {
      pause();
    }
    mosquitto_disconnect(mosq);
    mosquitto_loop_stop(mosq,false);
  } else {
	  rc = pub_loop(mosq);
  }

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	//client_config_cleanup(&cfg);
  if(cfg.know_bridge_connection){
	  bridge_shared_cleanup();
  }

	if(rc){
		err_printf(&cfg, "Error: %s\n", mosquitto_strerror(rc));
	}
	return rc;

cleanup:
	mosquitto_lib_cleanup();
	//client_config_cleanup(&cfg);
  if(cfg.know_bridge_connection){
    bridge_shared_cleanup();
  }

	return 1;
}
