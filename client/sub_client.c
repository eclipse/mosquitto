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

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef WIN32
#include <unistd.h>
#include <signal.h>
#else
#include <process.h>
#include <winsock2.h>
#define snprintf sprintf_s
#endif

#include <mosquitto.h>
#include <mqtt_protocol.h>
#include "client_shared.h"
#include "sub_client_output.h"

struct mosq_config cfg;
bool process_messages = true;
int msg_count = 0;
struct mosquitto *mosq = NULL;
int last_mid = 0;
static bool timed_out = false;
static int connack_result = 0;

#ifndef WIN32
void my_signal_handler(int signum)
{
	if(signum == SIGALRM || signum == SIGTERM || signum == SIGINT){
		process_messages = false;
		mosquitto_disconnect_v5(mosq, MQTT_RC_DISCONNECT_WITH_WILL_MSG, cfg.disconnect_props);
	}
	if(signum == SIGALRM){
		timed_out = true;
	}
}
#endif


void my_publish_callback(struct mosquitto *mosq, void *obj, int mid, int reason_code, const mosquitto_property *properties)
{
	UNUSED(obj);
	UNUSED(reason_code);
	UNUSED(properties);

	if(process_messages == false && (mid == last_mid || last_mid == 0)){
		mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
	}
}


void my_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message, const mosquitto_property *properties)
{
	int i;
	bool res;

	UNUSED(obj);
	UNUSED(properties);

	if(process_messages == false) return;

	if(cfg.retained_only && !message->retain && process_messages){
		process_messages = false;
		if(last_mid == 0){
			mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
		}
		return;
	}

	if(message->retain && cfg.no_retain) return;
	if(cfg.filter_outs){
		for(i=0; i<cfg.filter_out_count; i++){
			mosquitto_topic_matches_sub(cfg.filter_outs[i], message->topic, &res);
			if(res) return;
		}
	}

	if(cfg.remove_retained && message->retain){
		mosquitto_publish(mosq, &last_mid, message->topic, 0, NULL, 1, true);
	}

	print_message(&cfg, message, properties);

	if(cfg.msg_count>0){
		msg_count++;
		if(cfg.msg_count == msg_count){
			process_messages = false;
			if(last_mid == 0){
				mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
			}
		}
	}
}

void my_connect_callback(struct mosquitto *mosq, void *obj, int result, int flags, const mosquitto_property *properties)
{
	int i;

	UNUSED(obj);
	UNUSED(flags);
	UNUSED(properties);

	connack_result = result;
	if(!result){
		mosquitto_subscribe_multiple(mosq, NULL, cfg.topic_count, cfg.topics, cfg.qos, cfg.sub_opts, cfg.subscribe_props);

		for(i=0; i<cfg.unsub_topic_count; i++){
			mosquitto_unsubscribe_v5(mosq, NULL, cfg.unsub_topics[i], cfg.unsubscribe_props);
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
		}
		mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
	}
}

void my_subscribe_callback(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
	int i;
	bool some_sub_allowed = (granted_qos[0] < 128);
	bool should_print = cfg.debug && !cfg.quiet;
	UNUSED(obj);

	if(should_print) printf("Subscribed (mid: %d): %d", mid, granted_qos[0]);
	for(i=1; i<qos_count; i++){
		if(should_print) printf(", %d", granted_qos[i]);
		some_sub_allowed |= (granted_qos[i] < 128);
	}
	if(should_print) printf("\n");

	if(some_sub_allowed == false){
		mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
		err_printf(&cfg, "All subscription requests were denied.\n");
	}

	if(cfg.exit_after_sub){
		mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
	}
}

void my_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	UNUSED(mosq);
	UNUSED(obj);
	UNUSED(level);

	printf("%s\n", str);
}

void print_version(void)
{
	int major, minor, revision;

	mosquitto_lib_version(&major, &minor, &revision);
	printf("mosquitto_sub version %s running on libmosquitto %d.%d.%d.\n", VERSION, major, minor, revision);
}

void print_usage(void)
{
	int major, minor, revision;

	mosquitto_lib_version(&major, &minor, &revision);
	printf("mosquitto_sub is a simple mqtt client that will subscribe to a set of topics and print all messages it receives.\n");
	printf("mosquitto_sub version %s running on libmosquitto %d.%d.%d.\n\n", VERSION, major, minor, revision);
	printf("Usage: mosquitto_sub {[-h host] [--unix path] [-p port] [-u username] [-P password] -t topic | -L URL [-t topic]}\n");
	printf("                     [-c] [-k keepalive] [-q qos] [-x session-expiry-interval]\n");
	printf("                     [-C msg_count] [-E] [-R] [--retained-only] [--remove-retained] [-T filter_out] [-U topic ...]\n");
	printf("                     [-F format]\n");
#ifndef WIN32
	printf("                     [-W timeout_secs]\n");
#endif
#ifdef WITH_SRV
	printf("                     [-A bind_address] [--nodelay] [-S]\n");
#else
	printf("                     [-A bind_address] [--nodelay]\n");
#endif
	printf("                     [-i id] [-I id_prefix]\n");
	printf("                     [-d] [-N] [--quiet] [-v]\n");
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
	printf("                     [-D command identifier value]\n");
	printf("       mosquitto_sub --help\n\n");
	printf(" -A : bind the outgoing socket to this host/ip address. Use to control which interface\n");
	printf("      the client communicates over.\n");
	printf(" -c : disable clean session/enable persistent client mode\n");
	printf("      When this argument is used, the broker will be instructed not to clean existing sessions\n");
	printf("      for the same client id when the client connects, and sessions will never expire when the\n");
	printf("      client disconnects. MQTT v5 clients can change their session expiry interval with the -x\n");
	printf("      argument.\n");
	printf(" -C : disconnect and exit after receiving the 'msg_count' messages.\n");
	printf(" -d : enable debug messages.\n");
	printf(" -D : Define MQTT v5 properties. See the documentation for more details.\n");
	printf(" -E : Exit once all subscriptions have been acknowledged by the broker.\n");
	printf(" -F : output format.\n");
	printf(" -h : mqtt host to connect to. Defaults to localhost.\n");
	printf(" -i : id to use for this client. Defaults to mosquitto_sub_ appended with the process id.\n");
	printf(" -I : define the client id as id_prefix appended with the process id. Useful for when the\n");
	printf("      broker is using the clientid_prefixes option.\n");
	printf(" -k : keep alive in seconds for this client. Defaults to 60.\n");
	printf(" -L : specify user, password, hostname, port and topic as a URL in the form:\n");
	printf("      mqtt(s)://[username[:password]@]host[:port]/topic\n");
	printf(" -N : do not add an end of line character when printing the payload.\n");
	printf(" -p : network port to connect to. Defaults to 1883 for plain MQTT and 8883 for MQTT over TLS.\n");
	printf(" -P : provide a password\n");
	printf(" -q : quality of service level to use for the subscription. Defaults to 0.\n");
	printf(" -R : do not print stale messages (those with retain set).\n");
#ifdef WITH_SRV
	printf(" -S : use SRV lookups to determine which host to connect to.\n");
#endif
	printf(" -t : mqtt topic to subscribe to. May be repeated multiple times.\n");
	printf(" -T : topic string to filter out of results. May be repeated.\n");
	printf(" -u : provide a username\n");
	printf(" -U : unsubscribe from a topic. May be repeated.\n");
	printf(" -v : print published messages verbosely.\n");
	printf(" -V : specify the version of the MQTT protocol to use when connecting.\n");
	printf("      Can be mqttv5, mqttv311 or mqttv31. Defaults to mqttv311.\n");
#ifndef WIN32
	printf(" -W : Specifies a timeout in seconds how long to process incoming MQTT messages.\n");
#endif
	printf(" -x : Set the session-expiry-interval property on the CONNECT packet. Applies to MQTT v5\n");
	printf("      clients only. Set to 0-4294967294 to specify the session will expire in that many\n");
	printf("      seconds after the client disconnects, or use -1, 4294967295, or ∞ for a session\n");
	printf("      that does not expire. Defaults to -1 if -c is also given, or 0 if -c not given.\n");
	printf(" --help : display this message.\n");
	printf(" --nodelay : disable Nagle's algorithm, to reduce socket sending latency at the possible\n");
	printf("             expense of more packets being sent.\n");
	printf(" --pretty : print formatted output rather than minimised output when using the\n");
	printf("            JSON output format option.\n");
	printf(" --quiet : don't print error messages.\n");
	printf(" --random-filter : only print a percentage of received messages. Set to 100 to have all\n");
	printf("                   messages printed, 50.0 to have half of the messages received on average\n");
	printf("                   printed, and so on.\n");
	printf(" --retained-only : only handle messages with the retained flag set, and exit when the\n");
	printf("                   first non-retained message is received.\n");
	printf(" --remove-retained : send a message to the server to clear any received retained messages\n");
	printf("                     Use -T to filter out messages you do not want to be cleared.\n");
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
	printf("            certificate based communication.\n");
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
	printf(" --tls-engine : If set, enables the use of a SSL engine device.\n");
	printf(" --tls-engine-kpass-sha1 : SHA1 of the key password to be used with the selected SSL engine.\n");
	printf(" --tls-use-os-certs : Load and trust OS provided CA certificates.\n");
#ifdef FINAL_WITH_TLS_PSK
	printf(" --psk : pre-shared-key in hexadecimal (no leading 0x) to enable TLS-PSK mode.\n");
	printf(" --psk-identity : client identity string for TLS-PSK mode.\n");
#endif
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
	int rc;
#ifndef WIN32
		struct sigaction sigact;
#endif

	mosquitto_lib_init();

	rand_init();

	rc = client_config_load(&cfg, CLIENT_SUB, argc, argv);
	if(rc){
		if(rc == 2){
			/* --help */
			print_usage();
		}else if(rc == 3){
			/* --version */
			print_version();
		}else{
			fprintf(stderr, "\nUse 'mosquitto_sub --help' to see usage.\n");
		}
		goto cleanup;
	}

	if(cfg.no_retain && cfg.retained_only){
		fprintf(stderr, "\nError: Combining '-R' and '--retained-only' makes no sense.\n");
		goto cleanup;
	}

	if(client_id_generate(&cfg)){
		goto cleanup;
	}

	mosq = mosquitto_new(cfg.id, cfg.clean_session, &cfg);
	if(!mosq){
		switch(errno){
			case ENOMEM:
				err_printf(&cfg, "Error: Out of memory.\n");
				break;
			case EINVAL:
				err_printf(&cfg, "Error: Invalid id and/or clean_session.\n");
				break;
		}
		goto cleanup;
	}
	if(client_opts_set(mosq, &cfg)){
		goto cleanup;
	}
	if(cfg.debug){
		mosquitto_log_callback_set(mosq, my_log_callback);
	}
	mosquitto_subscribe_callback_set(mosq, my_subscribe_callback);
	mosquitto_connect_v5_callback_set(mosq, my_connect_callback);
	mosquitto_message_v5_callback_set(mosq, my_message_callback);

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

	rc = mosquitto_loop_forever(mosq, -1, 1);

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();

	if(cfg.msg_count>0 && rc == MOSQ_ERR_NO_CONN){
		rc = 0;
	}
	client_config_cleanup(&cfg);
	if(timed_out){
		err_printf(&cfg, "Timed out\n");
		return MOSQ_ERR_TIMEOUT;
	}else if(rc){
		err_printf(&cfg, "Error: %s\n", mosquitto_strerror(rc));
	}
	if(connack_result){
		return connack_result;
	}else{
		return rc;
	}

cleanup:
	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	client_config_cleanup(&cfg);
	return 1;
}

