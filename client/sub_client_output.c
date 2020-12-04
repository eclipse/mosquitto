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

#ifdef WIN32
   /* For rand_s on Windows */
#  define _CRT_RAND_S
#endif

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

#ifdef WITH_CJSON
#  include <cjson/cJSON.h>
#endif

#ifdef __APPLE__
#  include <sys/time.h>
#endif

#include <mosquitto.h>
#include <mqtt_protocol.h>
#include "client_shared.h"
#include "sub_client_output.h"

extern struct mosq_config cfg;

static int get_time(struct tm **ti, long *ns)
{
#ifdef WIN32
	SYSTEMTIME st;
#elif defined(__APPLE__)
	struct timeval tv;
#else
	struct timespec ts;
#endif
	time_t s;

#ifdef WIN32
	s = time(NULL);

	GetLocalTime(&st);
	*ns = st.wMilliseconds*1000000L;
#elif defined(__APPLE__)
	gettimeofday(&tv, NULL);
	s = tv.tv_sec;
	*ns = tv.tv_usec*1000;
#else
	if(clock_gettime(CLOCK_REALTIME, &ts) != 0){
		err_printf(&cfg, "Error obtaining system time.\n");
		return 1;
	}
	s = ts.tv_sec;
	*ns = ts.tv_nsec;
#endif

	*ti = localtime(&s);
	if(!(*ti)){
		err_printf(&cfg, "Error obtaining system time.\n");
		return 1;
	}

	return 0;
}


static void write_payload(const unsigned char *payload, int payloadlen, int hex, char align, char pad, int field_width, int precision)
{
	int i;
	int padlen;

	if(field_width > 0){
		if(payloadlen > field_width){
			payloadlen = field_width;
		}
		if(hex > 0){
			payloadlen /= 2;
			padlen = field_width - payloadlen*2;
		}else{
			padlen = field_width - payloadlen;
		}
	}else{
		padlen = field_width - payloadlen;
	}

	if(align != '-'){
		for(i=0; i<padlen; i++){
			putchar(pad);
		}
	}

	if(hex == 0){
		(void)fwrite(payload, 1, (size_t )payloadlen, stdout);
	}else if(hex == 1){
		for(i=0; i<payloadlen; i++){
			fprintf(stdout, "%02x", payload[i]);
		}
	}else if(hex == 2){
		for(i=0; i<payloadlen; i++){
			fprintf(stdout, "%02X", payload[i]);
		}
	}

	if(align == '-'){
		printf("%*s", padlen, "");
	}
}


#ifndef WITH_CJSON
static void write_json_payload(const char *payload, int payloadlen)
{
	int i;

	for(i=0; i<payloadlen; i++){
		if(payload[i] == '"' || payload[i] == '\\' || (payload[i] >=0 && payload[i] < 32)){
			printf("\\u%04x", payload[i]);
		}else{
			fputc(payload[i], stdout);
		}
	}
}
#endif


#ifdef WITH_CJSON
static int json_print_properties(cJSON *root, const mosquitto_property *properties)
{
	int identifier;
	uint8_t i8value = 0;
	uint16_t i16value = 0;
	uint32_t i32value = 0;
	char *strname = NULL, *strvalue = NULL;
	char *binvalue = NULL;
	cJSON *tmp, *prop_json, *user_json = NULL;
	const mosquitto_property *prop = NULL;

	prop_json = cJSON_CreateObject();
	if(prop_json == NULL){
		cJSON_Delete(prop_json);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(root, "properties", prop_json);

	for(prop=properties; prop != NULL; prop = mosquitto_property_next(prop)){
		tmp = NULL;
		identifier = mosquitto_property_identifier(prop);
		switch(identifier){
			case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
				mosquitto_property_read_byte(prop, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, &i8value, false);
				tmp = cJSON_CreateNumber(i8value);
				break;

			case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
				mosquitto_property_read_int32(prop, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, &i32value, false);
				tmp = cJSON_CreateNumber(i32value);
				break;

			case MQTT_PROP_CONTENT_TYPE:
			case MQTT_PROP_RESPONSE_TOPIC:
				mosquitto_property_read_string(prop, identifier, &strvalue, false);
				if(strvalue == NULL) return MOSQ_ERR_NOMEM;
				tmp = cJSON_CreateString(strvalue);
				free(strvalue);
				strvalue = NULL;
				break;

			case MQTT_PROP_CORRELATION_DATA:
				mosquitto_property_read_binary(prop, MQTT_PROP_CORRELATION_DATA, (void **)&binvalue, &i16value, false);
				if(binvalue == NULL) return MOSQ_ERR_NOMEM;
				tmp = cJSON_CreateString(binvalue);
				free(binvalue);
				binvalue = NULL;
				break;

			case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
				mosquitto_property_read_varint(prop, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, &i32value, false);
				tmp = cJSON_CreateNumber(i32value);
				break;

			case MQTT_PROP_TOPIC_ALIAS:
				mosquitto_property_read_int16(prop, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, &i16value, false);
				tmp = cJSON_CreateNumber(i16value);
				break;

			case MQTT_PROP_USER_PROPERTY:
				if(user_json == NULL){
					user_json = cJSON_CreateObject();
					if(user_json == NULL){
						return MOSQ_ERR_NOMEM;
					}
					cJSON_AddItemToObject(prop_json, "user-properties", user_json);
				}
				mosquitto_property_read_string_pair(prop, MQTT_PROP_USER_PROPERTY, &strname, &strvalue, false);
				if(strname == NULL || strvalue == NULL) return MOSQ_ERR_NOMEM;

				tmp = cJSON_CreateString(strvalue);
				free(strvalue);

				if(tmp == NULL){
					free(strname);
					return MOSQ_ERR_NOMEM;
				}
				cJSON_AddItemToObject(user_json, strname, tmp);
				free(strname);
				strname = NULL;
				strvalue = NULL;
				tmp = NULL; /* Don't add this to prop_json below */
				break;
		}
		if(tmp != NULL){
			cJSON_AddItemToObject(prop_json, mosquitto_property_identifier_to_string(identifier), tmp);
		}
	}
	return MOSQ_ERR_SUCCESS;
}
#endif


static int json_print(const struct mosquitto_message *message, const mosquitto_property *properties, const struct tm *ti, int ns, bool escaped, bool pretty)
{
	char buf[100];
#ifdef WITH_CJSON
	cJSON *root;
	cJSON *tmp;
	char *json_str;
	const char *return_parse_end;

	root = cJSON_CreateObject();
	if(root == NULL){
		return MOSQ_ERR_NOMEM;
	}

	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S.000000Z%z", ti);
	snprintf(&buf[strlen("2020-05-06T21:48:00.")], 9, "%06d", ns/1000);
	buf[strlen("2020-05-06T21:48:00.000000")] = 'Z';

	tmp = cJSON_CreateStringReference(buf);
	if(tmp == NULL){
		cJSON_Delete(root);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(root, "tst", tmp);

	tmp = cJSON_CreateString(message->topic);
	if(tmp == NULL){
		cJSON_Delete(root);
		return MOSQ_ERR_NOMEM;
	}

	cJSON_AddItemToObject(root, "topic", tmp);

	tmp = cJSON_CreateNumber(message->qos);
	if(tmp == NULL){
		cJSON_Delete(root);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(root, "qos", tmp);

	tmp = cJSON_CreateNumber(message->retain);
	if(tmp == NULL){
		cJSON_Delete(root);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(root, "retain", tmp);

	tmp = cJSON_CreateNumber(message->payloadlen);
	if(tmp == NULL){
		cJSON_Delete(root);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(root, "payloadlen", tmp);

	if(message->qos > 0){
		tmp = cJSON_CreateNumber(message->mid);
		if(tmp == NULL){
			cJSON_Delete(root);
			return MOSQ_ERR_NOMEM;
		}
		cJSON_AddItemToObject(root, "mid", tmp);
	}

	/* Properties */
	if(properties){
		if(json_print_properties(root, properties)){
			cJSON_Delete(root);
			return MOSQ_ERR_NOMEM;
		}
	}

	/* Payload */
	if(escaped){
		if(message->payload){
			tmp = cJSON_CreateString(message->payload);
		}else{
			tmp = cJSON_CreateNull();
		}
		if(tmp == NULL){
			cJSON_Delete(root);
			return MOSQ_ERR_NOMEM;
		}
		cJSON_AddItemToObject(root, "payload", tmp);
	}else{
		return_parse_end = NULL;
		if(message->payload){
			tmp = cJSON_ParseWithOpts(message->payload, &return_parse_end, true);
			if(tmp == NULL || return_parse_end != (char *)message->payload + message->payloadlen){
				cJSON_Delete(root);
				return MOSQ_ERR_INVAL;
			}
		}else{
			tmp = cJSON_CreateNull();
			if(tmp == NULL){
				cJSON_Delete(root);
				return MOSQ_ERR_INVAL;
			}
		}
		cJSON_AddItemToObject(root, "payload", tmp);
	}

	if(pretty){
		json_str = cJSON_Print(root);
	}else{
		json_str = cJSON_PrintUnformatted(root);
	}
	cJSON_Delete(root);

	fputs(json_str, stdout);
	free(json_str);
	
	return MOSQ_ERR_SUCCESS;
#else
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S.000000Z%z", ti);
	snprintf(&buf[strlen("2020-05-06T21:48:00.")], 9, "%06d", ns/1000);
	buf[strlen("2020-05-06T21:48:00.000000")] = 'Z';

	printf("{\"tst\":\"%s\",\"topic\":\"%s\",\"qos\":%d,\"retain\":%d,\"payloadlen\":%d,", buf, message->topic, message->qos, message->retain, message->payloadlen);
	if(message->qos > 0){
		printf("\"mid\":%d,", message->mid);
	}
	if(escaped){
		fputs("\"payload\":\"", stdout);
		write_json_payload(message->payload, message->payloadlen);
		fputs("\"}", stdout);
	}else{
		fputs("\"payload\":", stdout);
		write_payload(message->payload, message->payloadlen, 0, 0, 0, 0, 0);
		fputs("}", stdout);
	}
	
	return MOSQ_ERR_SUCCESS;
#endif
}


static void formatted_print_blank(char pad, int field_width)
{
	int i;
	for(i=0; i<field_width; i++){
		putchar(pad);
	}
}


static void formatted_print_int(int value, char align, char pad, int field_width)
{
	if(field_width == 0){
		printf("%d", value);
	}else{
		if(align == '-'){
			printf("%-*d", field_width, value);
		}else{
			if(pad == '0'){
				printf("%0*d", field_width, value);
			}else{
				printf("%*d", field_width, value);
			}
		}
	}
}


static void formatted_print_str(const char *value, char align, int field_width, int precision)
{
	if(field_width == 0 && precision == -1){
		fputs(value, stdout);
	}else{
		if(precision == -1){
			if(align == '-'){
				printf("%-*s", field_width, value);
			}else{
				printf("%*s", field_width, value);
			}
		}else if(field_width == 0){
			if(align == '-'){
				printf("%-.*s", precision, value);
			}else{
				printf("%.*s", precision, value);
			}
		}else{
			if(align == '-'){
				printf("%-*.*s", field_width, precision, value);
			}else{
				printf("%*.*s", field_width, precision, value);
			}
		}
	}
}

static void formatted_print_percent(const struct mosq_config *lcfg, const struct mosquitto_message *message, const mosquitto_property *properties, char format, char align, char pad, int field_width, int precision)
{
	struct tm *ti = NULL;
	long ns = 0;
	char buf[100];
	int rc;
	uint8_t i8value;
	uint16_t i16value;
	uint32_t i32value;
	char *binvalue, *strname, *strvalue;
	const mosquitto_property *prop;


	switch(format){
		case '%':
			fputc('%', stdout);
			break;

		case 'A':
			if(mosquitto_property_read_int16(properties, MQTT_PROP_TOPIC_ALIAS, &i16value, false)){
				formatted_print_int(i16value, align, pad, field_width);
			}else{
				formatted_print_blank(pad, field_width);
			}
			break;

		case 'C':
			if(mosquitto_property_read_string(properties, MQTT_PROP_CONTENT_TYPE, &strvalue, false)){
				formatted_print_str(strvalue, align, field_width, precision);
				free(strvalue);
			}else{
				formatted_print_blank(' ', field_width);
			}
			break;

		case 'D':
			if(mosquitto_property_read_binary(properties, MQTT_PROP_CORRELATION_DATA, (void **)&binvalue, &i16value, false)){
				fwrite(binvalue, 1, i16value, stdout);
				free(binvalue);
			}
			break;

		case 'E':
			if(mosquitto_property_read_int32(properties, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, &i32value, false)){
				formatted_print_int((int)i32value, align, pad, field_width);
			}else{
				formatted_print_blank(pad, field_width);
			}
			break;

		case 'F':
			if(mosquitto_property_read_byte(properties, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, &i8value, false)){
				formatted_print_int(i8value, align, pad, field_width);
			}else{
				formatted_print_blank(pad, field_width);
			}
			break;

		case 'I':
			if(!ti){
				if(get_time(&ti, &ns)){
					err_printf(lcfg, "Error obtaining system time.\n");
					return;
				}
			}
			if(strftime(buf, 100, "%FT%T%z", ti) != 0){
				formatted_print_str(buf, align, field_width, precision);
			}else{
				formatted_print_blank(' ', field_width);
			}
			break;

		case 'j':
			if(!ti){
				if(get_time(&ti, &ns)){
					err_printf(lcfg, "Error obtaining system time.\n");
					return;
				}
			}
			if(json_print(message, properties, ti, (int)ns, true, lcfg->pretty) != MOSQ_ERR_SUCCESS){
				err_printf(lcfg, "Error: Out of memory.\n");
				return;
			}
			break;

		case 'J':
			if(!ti){
				if(get_time(&ti, &ns)){
					err_printf(lcfg, "Error obtaining system time.\n");
					return;
				}
			}
			rc = json_print(message, properties, ti, (int)ns, false, lcfg->pretty);
			if(rc == MOSQ_ERR_NOMEM){
				err_printf(lcfg, "Error: Out of memory.\n");
				return;
			}else if(rc == MOSQ_ERR_INVAL){
				err_printf(lcfg, "Error: Message payload is not valid JSON on topic %s.\n", message->topic);
				return;
			}
			break;

		case 'l':
			formatted_print_int(message->payloadlen, align, pad, field_width);
			break;

		case 'm':
			formatted_print_int(message->mid, align, pad, field_width);
			break;

		case 'P':
			strname = NULL;
			strvalue = NULL;
			prop = mosquitto_property_read_string_pair(properties, MQTT_PROP_USER_PROPERTY, &strname, &strvalue, false);
			while(prop){
				printf("%s:%s", strname, strvalue);
				free(strname);
				free(strvalue);
				strname = NULL;
				strvalue = NULL;

				prop = mosquitto_property_read_string_pair(prop, MQTT_PROP_USER_PROPERTY, &strname, &strvalue, true);
				if(prop){
					fputc(' ', stdout);
				}
			}
			free(strname);
			free(strvalue);
			break;

		case 'p':
			write_payload(message->payload, message->payloadlen, 0, align, pad, field_width, precision);
			break;

		case 'q':
			fputc(message->qos + 48, stdout);
			break;

		case 'R':
			if(mosquitto_property_read_string(properties, MQTT_PROP_RESPONSE_TOPIC, &strvalue, false)){
				formatted_print_str(strvalue, align, field_width, precision);
				free(strvalue);
			}
			break;

		case 'r':
			if(message->retain){
				fputc('1', stdout);
			}else{
				fputc('0', stdout);
			}
			break;

		case 'S':
			if(mosquitto_property_read_varint(properties, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, &i32value, false)){
				formatted_print_int((int)i32value, align, pad, field_width);
			}else{
				formatted_print_blank(pad, field_width);
			}
			break;

		case 't':
			formatted_print_str(message->topic, align, field_width, precision);
			break;

		case 'U':
			if(!ti){
				if(get_time(&ti, &ns)){
					err_printf(lcfg, "Error obtaining system time.\n");
					return;
				}
			}
			if(strftime(buf, 100, "%s", ti) != 0){
				printf("%s.%09ld", buf, ns);
			}
			break;

		case 'x':
			write_payload(message->payload, message->payloadlen, 1, align, pad, field_width, precision);
			break;

		case 'X':
			write_payload(message->payload, message->payloadlen, 2, align, pad, field_width, precision);
			break;
	}
}


static void formatted_print(const struct mosq_config *lcfg, const struct mosquitto_message *message, const mosquitto_property *properties)
{
	size_t len;
	int i;
	struct tm *ti = NULL;
	long ns;
	char strf[3];
	char buf[100];
	char align, pad;
	int field_width, precision;

	len = strlen(lcfg->format);

	for(i=0; i<len; i++){
		if(lcfg->format[i] == '%'){
			align = 0;
			pad = ' ';
			field_width = 0;
			precision = -1;
			if(i < len-1){
				i++;
				/* Optional alignment */
				if(lcfg->format[i] == '-'){
					align = lcfg->format[i];
					if(i < len-1){
						i++;
					}
				}
				/* "%-040p" is allowed by this combination of checks, but isn't
				 * a valid format specifier, the '0' will be ignored. */
				/* Optional zero padding */
				if(lcfg->format[i] == '0'){
					pad = '0';
					if(i < len-1){
						i++;
					}
				}
				/* Optional field width */
				while(i < len-1 && lcfg->format[i] >= '0' && lcfg->format[i] <= '9'){
					field_width *= 10;
					field_width += lcfg->format[i]-'0';
					i++;
				}
				/* Optional precision */
				if(lcfg->format[i] == '.'){
					if(i < len-1){
						i++;
						precision = 0;
						while(i < len-1 && lcfg->format[i] >= '0' && lcfg->format[i] <= '9'){
							precision *= 10;
							precision += lcfg->format[i]-'0';
							i++;
						}
					}
				}

				if(i < len){
					formatted_print_percent(lcfg, message, properties, lcfg->format[i], align, pad, field_width, precision);
				}
			}
		}else if(lcfg->format[i] == '@'){
			if(i < len-1){
				i++;
				if(lcfg->format[i] == '@'){
					fputc('@', stdout);
				}else{
					if(!ti){
						if(get_time(&ti, &ns)){
							err_printf(lcfg, "Error obtaining system time.\n");
							return;
						}
					}

					strf[0] = '%';
					strf[1] = lcfg->format[i];
					strf[2] = 0;

					if(lcfg->format[i] == 'N'){
						printf("%09ld", ns);
					}else{
						if(strftime(buf, 100, strf, ti) != 0){
							fputs(buf, stdout);
						}
					}
				}
			}
		}else if(lcfg->format[i] == '\\'){
			if(i < len-1){
				i++;
				switch(lcfg->format[i]){
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
			fputc(lcfg->format[i], stdout);
		}
	}
	if(lcfg->eol){
		fputc('\n', stdout);
	}
	fflush(stdout);
}


void rand_init(void)
{
#ifndef WIN32
	struct tm *ti = NULL;
	long ns;

	if(!get_time(&ti, &ns)){
		srandom((unsigned int)ns);
	}
#endif
}


void print_message(struct mosq_config *cfg, const struct mosquitto_message *message, const mosquitto_property *properties)
{
#ifdef WIN32
	unsigned int r = 0;
#else
	long r = 0;
#endif

	if(cfg->random_filter < 10000){
#ifdef WIN32
		rand_s(&r);
#else
		r = random();
#endif
		if((r%10000) >= cfg->random_filter){
			return;
		}
	}
	if(cfg->format){
		formatted_print(cfg, message, properties);
	}else if(cfg->verbose){
		if(message->payloadlen){
			printf("%s ", message->topic);
			write_payload(message->payload, message->payloadlen, false, 0, 0, 0, 0);
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
			write_payload(message->payload, message->payloadlen, false, 0, 0, 0, 0);
			if(cfg->eol){
				printf("\n");
			}
			fflush(stdout);
		}
	}
}

