/*
Copyright (c) 2009-2016 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
*/

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <process.h>
#include <winsock2.h>
#define snprintf sprintf_s
#endif

#include <mosquitto.h>
#include "client_shared.h"

#if defined(WITH_TLS) && defined(WITH_TLS_TICKET)
static char *sessionfile = NULL;
#endif

bool process_messages = true;
int msg_count = 0;

static int get_time(struct tm **ti, long *ns)
{
#ifdef WIN32
	SYSTEMTIME st;
#else
	struct timespec ts;
#endif
	time_t s;

#ifdef WIN32
	s = time(NULL);

	GetLocalTime(&st);
	*ns = st.wMilliseconds*1000000L;
#else
	if(clock_gettime(CLOCK_REALTIME, &ts) != 0){
		fprintf(stderr, "Error obtaining system time.\n");
		return 1;
	}
	s = ts.tv_sec;
	*ns = ts.tv_nsec;
#endif

	*ti = localtime(&s);
	if(!(*ti)){
		fprintf(stderr, "Error obtaining system time.\n");
		return 1;
	}

	return 0;
}

static void write_payload(const unsigned char *payload, int payloadlen, bool hex)
{
	int i;

	if(!hex){
		(void)fwrite(payload, 1, payloadlen, stdout);
	}else{
		for(i=0; i<payloadlen; i++){
			fprintf(stdout, "%x", payload[i]);
		}
	}
}

void write_json_payload(const char *payload, int payloadlen)
{
	int i;

	for(i=0; i<payloadlen; i++){
		if(payload[i] == '"' || payload[i] == '\\' || (payload[i] >=0 && payload[i] < 32)){
			printf("\\u%04d", payload[i]);
		}else{
			fputc(payload[i], stdout);
		}
	}
}

void json_print(const struct mosquitto_message *message, const struct tm *ti, bool escaped)
{
	char buf[100];

	strftime(buf, 100, "%s", ti);
	printf("{\"tst\":%s,\"topic\":\"%s\",\"qos\":%d,\"retain\":%d,\"payloadlen\":%d,", buf, message->topic, message->qos, message->retain, message->payloadlen);
	if(message->qos > 0){
		printf("\"mid\":%d,", message->mid);
	}
	if(escaped){
		fputs("\"payload\":\"", stdout);
		write_json_payload(message->payload, message->payloadlen);
		fputs("\"}", stdout);
	}else{
		fputs("\"payload\":", stdout);
		write_payload(message->payload, message->payloadlen, false);
		fputs("}", stdout);
	}
}

void formatted_print(const struct mosq_config *cfg, const struct mosquitto_message *message)
{
	int len;
	int i;
	struct tm *ti = NULL;
	long ns;
	char strf[3];
	char buf[100];

	len = strlen(cfg->format);

	for(i=0; i<len; i++){
		if(cfg->format[i] == '%'){
			if(i < len-1){
				i++;
				switch(cfg->format[i]){
					case '%':
						fputc('%', stdout);
						break;

					case 'I':
						if(!ti){
							if(get_time(&ti, &ns)){
								fprintf(stderr, "Error obtaining system time.\n");
								return;
							}
						}
						if(strftime(buf, 100, "%FT%T%z", ti) != 0){
							fputs(buf, stdout);
						}
						break;

					case 'j':
						if(!ti){
							if(get_time(&ti, &ns)){
								fprintf(stderr, "Error obtaining system time.\n");
								return;
							}
						}
						json_print(message, ti, true);
						break;

					case 'J':
						if(!ti){
							if(get_time(&ti, &ns)){
								fprintf(stderr, "Error obtaining system time.\n");
								return;
							}
						}
						json_print(message, ti, false);
						break;

					case 'l':
						printf("%d", message->payloadlen);
						break;

					case 'm':
						printf("%d", message->mid);
						break;

					case 'p':
						write_payload(message->payload, message->payloadlen, false);
						break;

					case 'q':
						fputc(message->qos + 48, stdout);
						break;

					case 'r':
						if(message->retain){
							fputc('1', stdout);
						}else{
							fputc('0', stdout);
						}
						break;

					case 't':
						fputs(message->topic, stdout);
						break;

					case 'U':
						if(!ti){
							if(get_time(&ti, &ns)){
								fprintf(stderr, "Error obtaining system time.\n");
								return;
							}
						}
						if(strftime(buf, 100, "%s", ti) != 0){
							printf("%s.%09ld", buf, ns);
						}
						break;

					case 'x':
						write_payload(message->payload, message->payloadlen, true);
						break;
				}
			}
		}else if(cfg->format[i] == '@'){
			if(i < len-1){
				i++;
				if(cfg->format[i] == '@'){
					fputc('@', stdout);
				}else{
					if(!ti){
						if(get_time(&ti, &ns)){
							fprintf(stderr, "Error obtaining system time.\n");
							return;
						}
					}

					strf[0] = '%';
					strf[1] = cfg->format[i];
					strf[2] = 0;

					if(cfg->format[i] == 'N'){
						printf("%09ld", ns);
					}else{
						if(strftime(buf, 100, strf, ti) != 0){
							fputs(buf, stdout);
						}
					}
				}
			}
		}else if(cfg->format[i] == '\\'){
			if(i < len-1){
				i++;
				switch(cfg->format[i]){
					case '\\':
						fputc('\\', stdout);
						break;

					case '0':
						fputc('\0', stdout);
						break;

					case 'a':
						fputc('\a', stdout);
						break;

					case 'e':
						fputc('\033', stdout);
						break;

					case 'n':
						fputc('\n', stdout);
						break;

					case 'r':
						fputc('\r', stdout);
						break;

					case 't':
						fputc('\t', stdout);
						break;

					case 'v':
						fputc('\v', stdout);
						break;
				}
			}
		}else{
			fputc(cfg->format[i], stdout);
		}
	}
	if(cfg->eol){
		fputc('\n', stdout);
	}
	fflush(stdout);
}


void print_message(struct mosq_config *cfg, const struct mosquitto_message *message)
{
	if(cfg->format){
		formatted_print(cfg, message);
	}else if(cfg->verbose){
		if(message->payloadlen){
			printf("%s ", message->topic);
			write_payload(message->payload, message->payloadlen, false);
			if(cfg->eol){
				printf("\n");
			}
		}else{
			if(cfg->eol){
				printf("%s (null)\n", message->topic);
			}
		}
		fflush(stdout);
	}else{
		if(message->payloadlen){
			write_payload(message->payload, message->payloadlen, false);
			if(cfg->eol){
				printf("\n");
			}
			fflush(stdout);
		}
	}
}


void my_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	struct mosq_config *cfg;
	int i;
	bool res;

	if(process_messages == false) return;

	assert(obj);
	cfg = (struct mosq_config *)obj;

	if(cfg->retained_only && !message->retain && process_messages){
		process_messages = false;
		mosquitto_disconnect(mosq);
		return;
	}

	if(message->retain && cfg->no_retain) return;
	if(cfg->filter_outs){
		for(i=0; i<cfg->filter_out_count; i++){
			mosquitto_topic_matches_sub(cfg->filter_outs[i], message->topic, &res);
			if(res) return;
		}
	}

	print_message(cfg, message);

	if(cfg->msg_count>0){
		msg_count++;
		if(cfg->msg_count == msg_count){
			process_messages = false;
			mosquitto_disconnect(mosq);
		}
	}
}

void my_connect_callback(struct mosquitto *mosq, void *obj, int result)
{
	int i;
	struct mosq_config *cfg;

	assert(obj);
	cfg = (struct mosq_config *)obj;

	if(!result){
#if defined(WITH_TLS) && defined(WITH_TLS_TICKET)
		if(sessionfile){
			char* pem_session_ptr=NULL;
			i = mosquitto_tls_session_get(mosq, &pem_session_ptr);
			if(i==MOSQ_ERR_SUCCESS && pem_session_ptr){
				if(client_write_file(sessionfile, pem_session_ptr) && !cfg->quiet){
					fprintf(stderr, "Error writing session file [%s]\n", sessionfile);
				}
			}
			if(pem_session_ptr){
				mosquitto_tls_session_free(pem_session_ptr);
			}
		}
#endif
		for(i=0; i<cfg->topic_count; i++){
			mosquitto_subscribe(mosq, NULL, cfg->topics[i], cfg->qos);
		}
		for(i=0; i<cfg->unsub_topic_count; i++){
			mosquitto_unsubscribe(mosq, NULL, cfg->unsub_topics[i]);
		}
	}else{
		if(result && !cfg->quiet){
			fprintf(stderr, "%s\n", mosquitto_connack_string(result));
		}
	}
}

void my_subscribe_callback(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
	int i;
	struct mosq_config *cfg;

	assert(obj);
	cfg = (struct mosq_config *)obj;

	if(!cfg->quiet) printf("Subscribed (mid: %d): %d", mid, granted_qos[0]);
	for(i=1; i<qos_count; i++){
		if(!cfg->quiet) printf(", %d", granted_qos[i]);
	}
	if(!cfg->quiet) printf("\n");
}

void my_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	printf("%s\n", str);
}

void print_usage(void)
{
	int major, minor, revision;

	mosquitto_lib_version(&major, &minor, &revision);
	printf("mosquitto_sub is a simple mqtt client that will subscribe to a single topic and print all messages it receives.\n");
	printf("mosquitto_sub version %s running on libmosquitto %d.%d.%d.\n\n", VERSION, major, minor, revision);
	printf("Usage: mosquitto_sub {[-h host] [-p port] [-u username [-P password]] -t topic | -L URL [-t topic]}\n");
	printf("                     [-c] [-k keepalive] [-q qos]\n");
	printf("                     [-C msg_count] [-R] [--retained-only] [-T filter_out] [-U topic ...]\n");
	printf("                     [-F format]\n");
#ifdef WITH_SRV
	printf("                     [-A bind_address] [-S]\n");
#else
	printf("                     [-A bind_address]\n");
#endif
	printf("                     [-i id] [-I id_prefix]\n");
	printf("                     [-d] [-N] [--quiet] [-v]\n");
	printf("                     [--will-topic [--will-payload payload] [--will-qos qos] [--will-retain]]\n");
#ifdef WITH_TLS
	printf("                     [{--cafile file | --capath dir} [--cert file] [--key file]\n");
	printf("                      [--ciphers ciphers] [--insecure]]\n");
#ifdef WITH_TLS_PSK
	printf("                     [--psk hex-key --psk-identity identity [--ciphers ciphers]]\n");
#endif
#ifdef WITH_TLS_TICKET
	printf("                     [--session session_file]\n");
#endif
#endif
#ifdef WITH_SOCKS
	printf("                     [--proxy socks-url]\n");
#endif
	printf("       mosquitto_sub --help\n\n");
	printf(" -A : bind the outgoing socket to this host/ip address. Use to control which interface\n");
	printf("      the client communicates over.\n");
	printf(" -c : disable 'clean session' (store subscription and pending messages when client disconnects).\n");
	printf(" -C : disconnect and exit after receiving the 'msg_count' messages.\n");
	printf(" -d : enable debug messages.\n");
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
	printf(" -P : provide a password (requires MQTT 3.1 broker)\n");
	printf(" -q : quality of service level to use for the subscription. Defaults to 0.\n");
	printf(" -R : do not print stale messages (those with retain set).\n");
#ifdef WITH_SRV
	printf(" -S : use SRV lookups to determine which host to connect to.\n");
#endif
	printf(" -t : mqtt topic to subscribe to. May be repeated multiple times.\n");
	printf(" -T : topic string to filter out of results. May be repeated.\n");
	printf(" -u : provide a username (requires MQTT 3.1 broker)\n");
	printf(" -U : unsubscribe from a topic. May be repeated.\n");
	printf(" -v : print published messages verbosely.\n");
	printf(" -V : specify the version of the MQTT protocol to use when connecting.\n");
	printf("      Can be mqttv31 or mqttv311. Defaults to mqttv311.\n");
	printf(" --help : display this message.\n");
	printf(" --quiet : don't print error messages.\n");
	printf(" --retained-only : only handle messages with the retained flag set, and exit when the\n");
	printf("                   first non-retained message is received.\n");
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
	printf(" --ciphers : openssl compatible list of TLS ciphers to support.\n");
	printf(" --tls-version : TLS protocol version, can be one of tlsv1.2 tlsv1.1 or tlsv1.\n");
	printf("                 Defaults to tlsv1.2 if available.\n");
	printf(" --insecure : do not check that the server certificate hostname matches the remote\n");
	printf("              hostname. Using this option means that you cannot be sure that the\n");
	printf("              remote host is the server you wish to connect to and so is insecure.\n");
	printf("              Do not use this option in a production environment.\n");
#ifdef WITH_TLS_PSK
	printf(" --psk : pre-shared-key in hexadecimal (no leading 0x) to enable TLS-PSK mode.\n");
	printf(" --psk-identity : client identity string for TLS-PSK mode.\n");
#endif
#  ifdef WITH_TLS_TICKET
	printf(" --session : File to cache session in between runs.\n");
#  endif
#endif
#ifdef WITH_SOCKS
	printf(" --proxy : SOCKS5 proxy URL of the form:\n");
	printf("           socks5h://[username[:password]@]hostname[:port]\n");
	printf("           Only \"none\" and \"username\" authentication is supported.\n");
#endif
	printf("\nSee http://mosquitto.org/ for more information.\n\n");
}

int main(int argc, char *argv[])
{
	struct mosq_config cfg;
	struct mosquitto *mosq = NULL;
	int rc;
	
	memset(&cfg, 0, sizeof(struct mosq_config));
	rc = client_config_load(&cfg, CLIENT_SUB, argc, argv);
	if(rc){
		client_config_cleanup(&cfg);
		if(rc == 2){
			/* --help */
			print_usage();
		}else{
			fprintf(stderr, "\nUse 'mosquitto_sub --help' to see usage.\n");
		}
		return 1;
	}

#if defined(WITH_TLS) && defined(WITH_TLS_TICKET)
	sessionfile = cfg.sessionfile;
#endif

	if(cfg.no_retain && cfg.retained_only){
		fprintf(stderr, "\nError: Combining '-R' and '--retained-only' makes no sense.\n");
		return 1;
	}

	mosquitto_lib_init();

	if(client_id_generate(&cfg, "mosqsub")){
		return 1;
	}

	mosq = mosquitto_new(cfg.id, cfg.clean_session, &cfg);
	if(!mosq){
		switch(errno){
			case ENOMEM:
				if(!cfg.quiet) fprintf(stderr, "Error: Out of memory.\n");
				break;
			case EINVAL:
				if(!cfg.quiet) fprintf(stderr, "Error: Invalid id and/or clean_session.\n");
				break;
		}
		mosquitto_lib_cleanup();
		return 1;
	}
	if(client_opts_set(mosq, &cfg)){
		return 1;
	}
	if(cfg.debug){
		mosquitto_log_callback_set(mosq, my_log_callback);
		mosquitto_subscribe_callback_set(mosq, my_subscribe_callback);
	}
	mosquitto_connect_callback_set(mosq, my_connect_callback);
	mosquitto_message_callback_set(mosq, my_message_callback);

#if defined(WITH_TLS) && defined(WITH_TLS_TICKET)
	if(sessionfile){
		char* pem_session = NULL;
		rc=0;
		if(client_read_file(sessionfile, &pem_session) == 0){
			rc = mosquitto_tls_session_set(mosq, pem_session);
			free(pem_session);
		}
		if(rc) return rc;
	}
#endif

	rc = client_connect(mosq, &cfg);
	if(rc) return rc;


	rc = mosquitto_loop_forever(mosq, -1, 1);

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();

	if(cfg.msg_count>0 && rc == MOSQ_ERR_NO_CONN){
		rc = 0;
	}
	if(rc){
		fprintf(stderr, "Error: %s\n", mosquitto_strerror(rc));
	}
	return rc;
}

