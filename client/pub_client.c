/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
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
static bool first_publish = true;
static int last_mid = -1;
static int last_mid_sent = -1;
static char *line_buf = NULL;
static int line_buf_len = 1024;
static bool disconnect_sent = false;
static int publish_count = 0;
static bool ready_for_repeat = false;
static volatile int status = STATUS_CONNECTING;
static int connack_result = 0;

#ifdef WIN32
static uint64_t next_publish_tv;

static void set_repeat_time(void)
{
	uint64_t ticks = GetTickCount64();
	next_publish_tv = ticks + cfg.repeat_delay.tv_sec*1000 + cfg.repeat_delay.tv_usec/1000;
}

static int check_repeat_time(void)
{
	uint64_t ticks = GetTickCount64();

	if(ticks > next_publish_tv){
		return 1;
	}else{
		return 0;
	}
}
#else

static struct timeval next_publish_tv;

static void set_repeat_time(void)
{
	gettimeofday(&next_publish_tv, NULL);
	next_publish_tv.tv_sec += cfg.repeat_delay.tv_sec;
	next_publish_tv.tv_usec += cfg.repeat_delay.tv_usec;

	next_publish_tv.tv_sec += next_publish_tv.tv_usec/1000000;
	next_publish_tv.tv_usec = next_publish_tv.tv_usec%1000000;
}

static int check_repeat_time(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	if(tv.tv_sec > next_publish_tv.tv_sec){
		return 1;
	}else if(tv.tv_sec == next_publish_tv.tv_sec
			&& tv.tv_usec > next_publish_tv.tv_usec){

		return 1;
	}
	return 0;
}
#endif

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
	ready_for_repeat = false;
	if(cfg.protocol_version == MQTT_PROTOCOL_V5 && cfg.have_topic_alias && first_publish == false){
		return mosquitto_publish_v5(mosq, mid, NULL, payloadlen, payload, qos, retain, cfg.publish_props);
	}else{
		first_publish = false;
		return mosquitto_publish_v5(mosq, mid, topic, payloadlen, payload, qos, retain, cfg.publish_props);
	}
}


void my_connect_callback(struct mosquitto *mosq, void *obj, int result, int flags, const mosquitto_property *properties)
{
	int rc = MOSQ_ERR_SUCCESS;

	UNUSED(obj);
	UNUSED(flags);
	UNUSED(properties);

	connack_result = result;

	if(!result){
		switch(cfg.pub_mode){
			case MSGMODE_CMD:
			case MSGMODE_FILE:
			case MSGMODE_STDIN_FILE:
				rc = my_publish(mosq, &mid_sent, cfg.topic, cfg.msglen, cfg.message, cfg.qos, cfg.retain);
				break;
			case MSGMODE_NULL:
				rc = my_publish(mosq, &mid_sent, cfg.topic, 0, NULL, cfg.qos, cfg.retain);
				break;
			case MSGMODE_STDIN_LINE:
				status = STATUS_CONNACK_RECVD;
				break;
		}
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
			// let the loop know that this is an unrecoverable connection
			status = STATUS_NOHOPE;
		}
	}
}


void my_publish_callback(struct mosquitto *mosq, void *obj, int mid, int reason_code, const mosquitto_property *properties)
{
	char *reason_string = NULL;
	UNUSED(obj);
	UNUSED(properties);

	last_mid_sent = mid;
	if(reason_code > 127){
		err_printf(&cfg, "Warning: Publish %d failed: %s.\n", mid, mosquitto_reason_string(reason_code));
		mosquitto_property_read_string(properties, MQTT_PROP_REASON_STRING, &reason_string, false);
		if(reason_string){
			err_printf(&cfg, "%s\n", reason_string);
			free(reason_string);
		}
	}
	publish_count++;

	if(cfg.pub_mode == MSGMODE_STDIN_LINE){
		if(mid == last_mid){
			mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
			disconnect_sent = true;
		}
	}else if(publish_count < cfg.repeat_count){
		ready_for_repeat = true;
		set_repeat_time();
	}else if(disconnect_sent == false){
		mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
		disconnect_sent = true;
	}
}


int pub_shared_init(void)
{
	line_buf = malloc((size_t )line_buf_len);
	if(!line_buf){
		err_printf(&cfg, "Error: Out of memory.\n");
		return 1;
	}
	return 0;
}


int pub_stdin_line_loop(struct mosquitto *mosq)
{
	char *buf2;
	int buf_len_actual = 0;
	int pos;
	int rc = MOSQ_ERR_SUCCESS;
	int read_len;
	bool stdin_finished = false;

	mosquitto_loop_start(mosq);
	stdin_finished = false;
	do{
		if(status == STATUS_CONNECTING){
#ifdef WIN32
			Sleep(100);
#else
			struct timespec ts;
			ts.tv_sec = 0;
			ts.tv_nsec = 100000000;
			nanosleep(&ts, NULL);
#endif
		}

		if(status == STATUS_NOHOPE){
			return MOSQ_ERR_CONN_REFUSED;
		}

		if(status == STATUS_CONNACK_RECVD){
			pos = 0;
			read_len = line_buf_len;
			while(status == STATUS_CONNACK_RECVD && fgets(&line_buf[pos], read_len, stdin)){
				buf_len_actual = (int )strlen(line_buf);
				if(line_buf[buf_len_actual-1] == '\n'){
					line_buf[buf_len_actual-1] = '\0';
					rc = my_publish(mosq, &mid_sent, cfg.topic, buf_len_actual-1, line_buf, cfg.qos, cfg.retain);
					pos = 0;
					if(rc){
						err_printf(&cfg, "Error: Publish returned %d.\n", rc);
						if(cfg.qos>0) return rc;
					}
					break;
				}else{
					line_buf_len += 1024;
					pos += 1023;
					read_len = 1024;
					buf2 = realloc(line_buf, (size_t )line_buf_len);
					if(!buf2){
						err_printf(&cfg, "Error: Out of memory.\n");
						return MOSQ_ERR_NOMEM;
					}
					line_buf = buf2;
				}
			}
			if(pos != 0){
				rc = my_publish(mosq, &mid_sent, cfg.topic, buf_len_actual, line_buf, cfg.qos, cfg.retain);
				if(rc){
					err_printf(&cfg, "Error: Publish returned %d.\n", rc);
					if(cfg.qos>0) return rc;
				}
			}
			if(feof(stdin)){
				if(mid_sent == -1){
					/* Empty file */
					mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
					disconnect_sent = true;
					status = STATUS_DISCONNECTING;
				}else{
					last_mid = mid_sent;
					status = STATUS_WAITING;
				}
				stdin_finished = true;
			}else if(status == STATUS_DISCONNECTED){
				/* Not end of stdin, so we've lost our connection and must
				 * reconnect */
			}
		}

		if(status == STATUS_WAITING){
			if(last_mid_sent == last_mid && disconnect_sent == false){
				mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
				disconnect_sent = true;
			}
#ifdef WIN32
			Sleep(100);
#else
			struct timespec ts;
			ts.tv_sec = 0;
			ts.tv_nsec = 100000000;
			nanosleep(&ts, NULL);
#endif
		}
	}while(stdin_finished == false);
	mosquitto_loop_stop(mosq, false);

	if(status == STATUS_DISCONNECTED){
		return MOSQ_ERR_SUCCESS;
	}else{
		return rc;
	}
}


int pub_other_loop(struct mosquitto *mosq)
{
	int rc;
	int loop_delay = 1000;

	if(cfg.repeat_count > 1 && (cfg.repeat_delay.tv_sec == 0 || cfg.repeat_delay.tv_usec != 0)){
		loop_delay = (int )cfg.repeat_delay.tv_usec / 2000;
	}

	do{
		rc = mosquitto_loop(mosq, loop_delay, 1);
		if(ready_for_repeat && check_repeat_time()){
			rc = MOSQ_ERR_SUCCESS;
			switch(cfg.pub_mode){
				case MSGMODE_CMD:
				case MSGMODE_FILE:
				case MSGMODE_STDIN_FILE:
					rc = my_publish(mosq, &mid_sent, cfg.topic, cfg.msglen, cfg.message, cfg.qos, cfg.retain);
					break;
				case MSGMODE_NULL:
					rc = my_publish(mosq, &mid_sent, cfg.topic, 0, NULL, cfg.qos, cfg.retain);
					break;
			}
			if(rc){
				err_printf(&cfg, "Error sending repeat publish: %s", mosquitto_strerror(rc));
			}
		}
	}while(rc == MOSQ_ERR_SUCCESS);

	if(status == STATUS_DISCONNECTED){
		return MOSQ_ERR_SUCCESS;
	}else{
		return rc;
	}
}


int pub_shared_loop(struct mosquitto *mosq)
{
	if(cfg.pub_mode == MSGMODE_STDIN_LINE){
		return pub_stdin_line_loop(mosq);
	}else{
		return pub_other_loop(mosq);
	}
}


void pub_shared_cleanup(void)
{
	free(line_buf);
}


void print_version(void)
{
	int major, minor, revision;

	mosquitto_lib_version(&major, &minor, &revision);
	printf("mosquitto_pub version %s running on libmosquitto %d.%d.%d.\n", VERSION, major, minor, revision);
}

void print_usage(void)
{
	int major, minor, revision;

	mosquitto_lib_version(&major, &minor, &revision);
	printf("mosquitto_pub is a simple mqtt client that will publish a message on a single topic and exit.\n");
	printf("mosquitto_pub version %s running on libmosquitto %d.%d.%d.\n\n", VERSION, major, minor, revision);
	printf("Usage: mosquitto_pub {[-h host] [--unix path] [-p port] [-u username] [-P password] -t topic | -L URL}\n");
	printf("                     {-f file | -l | -n | -m message}\n");
	printf("                     [-c] [-k keepalive] [-q qos] [-r] [--repeat N] [--repeat-delay time] [-x session-expiry]\n");
#ifdef WITH_SRV
	printf("                     [-A bind_address] [--nodelay] [-S]\n");
#else
	printf("                     [-A bind_address] [--nodelay]\n");
#endif
	printf("                     [-i id] [-I id_prefix]\n");
	printf("                     [-d] [--quiet]\n");
	printf("                     [-M max_inflight]\n");
	printf("                     [-u username [-P password]]\n");
	printf("                     [--will-topic [--will-payload payload] [--will-qos qos] [--will-retain]]\n");
#ifdef WITH_TLS
	printf("                     [{--cafile file | --capath dir} [--cert file] [--key file]\n");
	printf("                       [--ciphers ciphers] [--insecure]\n");
	printf("                       [--tls-alpn protocol]\n");
	printf("                       [--tls-engine engine] [--keyform keyform] [--tls-engine-kpass-sha1]]\n");
	printf("                       [--tls-use-os-certs]\n");
#ifdef FINAL_WITH_TLS_PSK
	printf("                     [--psk hex-key --psk-identity identity [--ciphers ciphers]]\n");
#endif
#endif
#ifdef WITH_SOCKS
	printf("                     [--proxy socks-url]\n");
#endif
	printf("                     [--property command identifier value]\n");
	printf("                     [-D command identifier value]\n");
	printf("       mosquitto_pub --help\n\n");
	printf(" -A : bind the outgoing socket to this host/ip address. Use to control which interface\n");
	printf("      the client communicates over.\n");
	printf(" -d : enable debug messages.\n");
	printf(" -c : disable clean session/enable persistent client mode\n");
	printf("      When this argument is used, the broker will be instructed not to clean existing sessions\n");
	printf("      for the same client id when the client connects, and sessions will never expire when the\n");
	printf("      client disconnects. MQTT v5 clients can change their session expiry interval with the -x\n");
	printf("      argument.\n");
	printf(" -D : Define MQTT v5 properties. See the documentation for more details.\n");
	printf(" -f : send the contents of a file as the message.\n");
	printf(" -h : mqtt host to connect to. Defaults to localhost.\n");
	printf(" -i : id to use for this client. Defaults to mosquitto_pub_ appended with the process id.\n");
	printf(" -I : define the client id as id_prefix appended with the process id. Useful for when the\n");
	printf("      broker is using the clientid_prefixes option.\n");
	printf(" -k : keep alive in seconds for this client. Defaults to 60.\n");
	printf(" -L : specify user, password, hostname, port and topic as a URL in the form:\n");
	printf("      mqtt(s)://[username[:password]@]host[:port]/topic\n");
	printf(" -l : read messages from stdin, sending a separate message for each line.\n");
	printf(" -m : message payload to send.\n");
	printf(" -M : the maximum inflight messages for QoS 1/2..\n");
	printf(" -n : send a null (zero length) message.\n");
	printf(" -p : network port to connect to. Defaults to 1883 for plain MQTT and 8883 for MQTT over TLS.\n");
	printf(" -P : provide a password\n");
	printf(" -q : quality of service level to use for all messages. Defaults to 0.\n");
	printf(" -r : message should be retained.\n");
	printf(" -s : read message from stdin, sending the entire input as a message.\n");
#ifdef WITH_SRV
	printf(" -S : use SRV lookups to determine which host to connect to.\n");
#endif
	printf(" -t : mqtt topic to publish to.\n");
	printf(" -u : provide a username\n");
	printf(" -V : specify the version of the MQTT protocol to use when connecting.\n");
	printf("      Can be mqttv5, mqttv311 or mqttv31. Defaults to mqttv311.\n");
	printf(" -x : Set the session-expiry-interval property on the CONNECT packet. Applies to MQTT v5\n");
	printf("      clients only. Set to 0-4294967294 to specify the session will expire in that many\n");
	printf("      seconds after the client disconnects, or use -1, 4294967295, or ∞ for a session\n");
	printf("      that does not expire. Defaults to -1 if -c is also given, or 0 if -c not given.\n");
	printf(" --help : display this message.\n");
	printf(" --nodelay : disable Nagle's algorithm, to reduce socket sending latency at the possible\n");
	printf("             expense of more packets being sent.\n");
	printf(" --quiet : don't print error messages.\n");
	printf(" --repeat : if publish mode is -f, -m, or -s, then repeat the publish N times.\n");
	printf(" --repeat-delay : if using --repeat, wait time seconds between publishes. Defaults to 0.\n");
	printf(" --unix : connect to a broker through a unix domain socket instead of a TCP socket,\n");
	printf("          e.g. /tmp/mosquitto.sock\n");
	printf(" --will-payload : payload for the client Will, which is sent by the broker in case of\n");
	printf("                  unexpected disconnection. If not given and will-topic is set, a zero\n");
	printf("                  length message will be sent.\n");
	printf(" --will-qos : QoS level for the client Will.\n");
	printf(" --will-retain : if given, make the client Will retained.\n");
	printf(" --will-topic : the topic on which to publish the client Will.\n");
#ifdef WITH_TLS
	printf(" --cafile : path to a file containing trusted CA certificates to enable encrypted\n");
	printf("            communication.\n");
	printf(" --capath : path to a directory containing trusted CA certificates to enable encrypted\n");
	printf("            communication.\n");
	printf(" --cert : client certificate for authentication, if required by server.\n");
	printf(" --key : client private key for authentication, if required by server.\n");
	printf(" --keyform : keyfile type, can be either \"pem\" or \"engine\".\n");
	printf(" --ciphers : openssl compatible list of TLS ciphers to support.\n");
	printf(" --tls-version : TLS protocol version, can be one of tlsv1.3 tlsv1.2 or tlsv1.1.\n");
	printf("                 Defaults to tlsv1.2 if available.\n");
	printf(" --insecure : do not check that the server certificate hostname matches the remote\n");
	printf("              hostname. Using this option means that you cannot be sure that the\n");
	printf("              remote host is the server you wish to connect to and so is insecure.\n");
	printf("              Do not use this option in a production environment.\n");
	printf(" --tls-engine : If set, enables the use of a TLS engine device.\n");
	printf(" --tls-engine-kpass-sha1 : SHA1 of the key password to be used with the selected SSL engine.\n");
	printf(" --tls-use-os-certs : Load and trust OS provided CA certificates.\n");
#  ifdef FINAL_WITH_TLS_PSK
	printf(" --psk : pre-shared-key in hexadecimal (no leading 0x) to enable TLS-PSK mode.\n");
	printf(" --psk-identity : client identity string for TLS-PSK mode.\n");
#  endif
#endif
#ifdef WITH_SOCKS
	printf(" --proxy : SOCKS5 proxy URL of the form:\n");
	printf("           socks5h://[username[:password]@]hostname[:port]\n");
	printf("           Only \"none\" and \"username\" authentication is supported.\n");
#endif
	printf("\nSee https://mosquitto.org/ for more information.\n\n");
}

int main(int argc, char *argv[])
{
	struct mosquitto *mosq = NULL;
	int rc;

	mosquitto_lib_init();

	if(pub_shared_init()) return 1;

	rc = client_config_load(&cfg, CLIENT_PUB, argc, argv);
	if(rc){
		if(rc == 2){
			/* --help */
			print_usage();
		}else if(rc == 3){
			print_version();
		}else{
			fprintf(stderr, "\nUse 'mosquitto_pub --help' to see usage.\n");
		}
		goto cleanup;
	}

#ifndef WITH_THREADING
	if(cfg.pub_mode == MSGMODE_STDIN_LINE){
		fprintf(stderr, "Error: '-l' mode not available, threading support has not been compiled in.\n");
		goto cleanup;
	}
#endif

	if(cfg.pub_mode == MSGMODE_STDIN_FILE){
		if(load_stdin()){
			err_printf(&cfg, "Error loading input from stdin.\n");
			goto cleanup;
		}
	}else if(cfg.file_input){
		if(load_file(cfg.file_input)){
			err_printf(&cfg, "Error loading input file \"%s\".\n", cfg.file_input);
			goto cleanup;
		}
	}

	if(!cfg.topic || cfg.pub_mode == MSGMODE_NONE){
		fprintf(stderr, "Error: Both topic and message must be supplied.\n");
		print_usage();
		goto cleanup;
	}


	if(client_id_generate(&cfg)){
		goto cleanup;
	}

	mosq = mosquitto_new(cfg.id, cfg.clean_session, NULL);
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
	if(cfg.debug){
		mosquitto_log_callback_set(mosq, my_log_callback);
	}
	mosquitto_connect_v5_callback_set(mosq, my_connect_callback);
	mosquitto_disconnect_v5_callback_set(mosq, my_disconnect_callback);
	mosquitto_publish_v5_callback_set(mosq, my_publish_callback);

	if(client_opts_set(mosq, &cfg)){
		goto cleanup;
	}

	rc = client_connect(mosq, &cfg);
	if(rc){
		goto cleanup;
	}

	rc = pub_shared_loop(mosq);

	if(cfg.message && cfg.pub_mode == MSGMODE_FILE){
		free(cfg.message);
		cfg.message = NULL;
	}
	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	client_config_cleanup(&cfg);
	pub_shared_cleanup();

	if(rc){
		err_printf(&cfg, "Error: %s\n", mosquitto_strerror(rc));
	}
	if(connack_result){
		return connack_result;
	}else{
		return rc;
	}

cleanup:
	mosquitto_lib_cleanup();
	client_config_cleanup(&cfg);
	pub_shared_cleanup();
	return 1;
}
