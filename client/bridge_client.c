/*
Copyright (c) 2017 Tifaifai Maupiti <tifaifai.maupiti@gmail.com>

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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <mosquitto.h>
#include "client_shared.h"

#define STATUS_CONNECTING 0
#define STATUS_CONNACK_RECVD 1
#define STATUS_WAITING 2

static bool connected = true;
static bool wait = true;

static char *topic = NULL;
static char *name = NULL;
static char *pattern = NULL;
static char *direction = NULL;
static char *local_prefix = NULL;
static char *remote_prefix = NULL;
static char *remote_add = NULL;
static char *msg = NULL;
static int remote_port;
static int qos = 0;
static char *username = NULL;
static char *password = NULL;

int run = 1;
int nb_line = 0;

struct bridge{
  char *name;
};

struct bridge_list{
  int bridge_list_count;
  struct bridge* bridge;
};

void show_bridges(struct bridge_list* bridges)
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
}

static void on_message(struct mosquitto *m, void *udata,const struct mosquitto_message *msg)
{
    struct bridge_list *bridges;
    bridges = (struct bridge_list*) udata;
    int valid_erase = 0;
    int i;

    if(!strcmp(msg->payload,"1")){
      bridges->bridge_list_count++;
      bridges->bridge = realloc(bridges->bridge, sizeof(struct bridge)*bridges->bridge_list_count);
      if(!bridges->bridge){
        printf("Error: Out of memory. 1\n");
        exit(-1);
      }

      bridges->bridge[bridges->bridge_list_count-1].name = malloc(sizeof(char)*strlen(msg->topic));
      if(!bridges->bridge[bridges->bridge_list_count-1].name){
        printf("Error: Out of memory. 2\n");
        exit(-1);
      }

      bridges->bridge[bridges->bridge_list_count-1].name = strdup(msg->topic);
      show_bridges(bridges);
    }else{
      if(bridges->bridge_list_count>0){
        for (i = 0; i < bridges->bridge_list_count; i++) {
          if(!strcmp(bridges->bridge[i].name,msg->topic)){
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
          show_bridges(bridges);
        }
      }else{
        bridges->bridge_list_count = 0;
      }
    }
}

void my_publish_callback(struct mosquitto *mosq, void *userdata, int mid)
{
    wait = false;
}

void my_disconnect_callback(struct mosquitto *mosq, void *obj, int rc)
{
	 connected = false;
	 mosquitto_loop_stop(mosq,false);
}

void print_usage(void)
{
    int major, minor, revision;

    mosquitto_lib_version(&major, &minor, &revision);
    printf("mosquitto_bridge is a simple mqtt client that will publish a message on a single topic on one broker to manage bridge dynamiclly with another and exit.\n");
    printf("mosquitto_bridge version %s running on libmosquitto %d.%d.%d.\n\n", VERSION, major, minor, revision);
    printf("Usage: mosquitto_bridge [-h local host] [-p local port] [-q qos] -a remote host -P remote port -t bridge pattern -D bridge direction -l local prefix -r remote prefix\n");
    printf("\n");
    printf("mosquitto_bridge --help\n\n");
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

void handle_sigint(int signal)
{
	run = 0;
}

int main(int argc, char *argv[])
{
    struct mosq_config cfg;
    struct mosquitto *mosq = NULL;
    struct bridge_list *bridges = NULL;
    void * ptrMosq = NULL;

    int rc,rc2;
    int msg_len;

    memset(&cfg, 0, sizeof(struct mosq_config));
    rc = client_config_load_bridge(&cfg, argc, argv);
    if(rc){
        client_config_cleanup(&cfg);
        if(rc == 2){
            /* --help */
            print_usage();
        }else{
            fprintf(stderr, "\nUse 'mosquitto_bridge --help' to see usage.\n");
        }
        return 1;
    }

    signal(SIGINT, handle_sigint);

    username = cfg.username;
  	password = cfg.password;

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
    }else if(cfg.bridgeType == BRIDGE_DEL){
        topic = strdup("$SYS/broker/bridge/del");
        name = cfg.bridge.name;

        msg_len = snprintf(NULL,0,"connection %s",name);
        msg_len++;
        msg = (char*) malloc(msg_len);
        snprintf(msg,msg_len,"connection %s",name);
    }

    mosquitto_lib_init();

    if(client_id_generate(&cfg, "mosqbridge")){
        return 1;
    }

    if(cfg.know_bridge_connection){
      bridges = malloc(sizeof(struct bridge_list));
      if(!bridges){
        printf("Error: Out of memory.\n");
        return 1;
      }
      ptrMosq = bridges;
    }

    mosq = mosquitto_new(cfg.id, true, ptrMosq);
    if(!mosq){
        switch(errno){
            case ENOMEM:
                fprintf(stderr, "Error: Out of memory.\n");
                break;
            case EINVAL:
                fprintf(stderr, "Error: Invalid id.\n");
                break;
        }
        mosquitto_lib_cleanup();
        return 1;
    }

    if(client_opts_set(mosq, &cfg)){
  		return 1;
  	}

    mosquitto_disconnect_callback_set(mosq, my_disconnect_callback);
    mosquitto_publish_callback_set(mosq, my_publish_callback);

    rc = client_connect(mosq, &cfg);
    if(rc) return rc;

    if(cfg.know_bridge_connection){
      mosquitto_subscribe(mosq,NULL,"$SYS/broker/connection/#",0);
      mosquitto_message_callback_set(mosq, on_message);
    }

    mosquitto_loop_start(mosq);

    if(cfg.know_bridge_connection){
      while (run) {
        pause();
      }
    }else{

      wait = true;
      printf("msg :\n%s\n",msg);
      rc2 = mosquitto_publish(mosq, NULL, topic,strlen(msg),msg, 0, false);
      if(rc2){
        fprintf(stderr, "Error: Publish returned %d, disconnecting.\n", rc2);
        mosquitto_disconnect(mosq);
      }
      while(wait)usleep(10000);
    }

    mosquitto_disconnect(mosq);

    mosquitto_loop_stop(mosq,false);

    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();

    if(rc){
        fprintf(stderr, "Error: %s\n", mosquitto_strerror(rc));
    }
    return rc;
}
