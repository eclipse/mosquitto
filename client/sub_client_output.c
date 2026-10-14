/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#ifdef WIN32
/* For rand_s on Windows */
#  define _CRT_RAND_S
#  include <fcntl.h>
#  include <io.h>
#endif

#include <assert.h>
#include <cjson/cJSON.h>
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

#undef uthash_malloc
#undef uthash_free
#include <uthash.h>


#ifdef __APPLE__
#  include <sys/time.h>
#endif

#include <mosquitto.h>
#include "client_shared.h"
#include "sub_client_output.h"

extern struct mosq_config cfg;

struct fieldoptions {
	int field_width;
	int precision;
	char hexsepchar;
	char align;
	char pad;
};

struct watch_topic {
	UT_hash_handle hh;
	char *topic;
	int line;
};
static int watch_max = 2;
static struct watch_topic *watch_items = NULL;


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


static const signed char nibble_to_hex[] = {
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};


static void hexsep(int xpos, int precision, char sepchar)
{
	if(precision > 0 && xpos%precision == (precision-1)){
		putchar(sepchar);
	}
}


static void write_payload(const unsigned char *payload, int payloadlen, int hex, struct fieldoptions *fopts)
{
	int i;
	int padlen;

	if(fopts->field_width > 0){
		if(payloadlen > fopts->field_width){
			payloadlen = fopts->field_width;
		}
		if(hex > 0){
			padlen = fopts->field_width - payloadlen*2;
		}else{
			padlen = fopts->field_width - payloadlen;
		}
	}else{
		padlen = fopts->field_width - payloadlen;
	}

	int xpos = 0;
	if(fopts->align != '-'){
		for(i=0; i<padlen; i++){
			putchar(fopts->pad);
			if(hex > 0){
				hexsep(xpos, fopts->precision, fopts->hexsepchar);
			}
			xpos++;
		}
	}

	if(hex == 0){
		(void)fwrite(payload, 1, (size_t )payloadlen, stdout);
	}else{
		signed char casemod = (hex == 1?0x20:0x00);
		for(i=0; i<payloadlen; i++){
			putchar(nibble_to_hex[((payload[i] & 0xF0) >> 4)] | casemod);
			hexsep(xpos, fopts->precision, fopts->hexsepchar);
			xpos += 1;

			putchar(nibble_to_hex[(payload[i] & 0x0F)] | casemod);
			if(i < payloadlen-1){
				hexsep(xpos, fopts->precision, fopts->hexsepchar);
				xpos += 1;
			}
		}
	}

	if(fopts->align == '-'){
		printf("%*s", padlen, "");
	}
}


static int json_print_properties(cJSON *root, const mosquitto_property *properties)
{
	int identifier;
	uint8_t i8value = 0;
	uint16_t i16value = 0;
	uint32_t i32value = 0;
	char *strname = NULL, *strvalue = NULL;
	char *binvalue = NULL;
	cJSON *tmp, *prop_json, *user_props = NULL, *user_json;
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
				if(strvalue == NULL){
					return MOSQ_ERR_NOMEM;
				}
				tmp = cJSON_CreateString(strvalue);
				free(strvalue);
				strvalue = NULL;
				break;

			case MQTT_PROP_CORRELATION_DATA:
				mosquitto_property_read_binary(prop, MQTT_PROP_CORRELATION_DATA, (void **)&binvalue, &i16value, false);
				if(binvalue == NULL){
					return MOSQ_ERR_NOMEM;
				}
				tmp = cJSON_CreateString(binvalue);
				free(binvalue);
				binvalue = NULL;
				break;

			case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
				mosquitto_property_read_varint(prop, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, &i32value, false);
				tmp = cJSON_CreateNumber(i32value);
				break;

			case MQTT_PROP_TOPIC_ALIAS:
				mosquitto_property_read_int16(prop, MQTT_PROP_TOPIC_ALIAS, &i16value, false);
				tmp = cJSON_CreateNumber(i16value);
				break;

			case MQTT_PROP_USER_PROPERTY:
				if(user_props == NULL){
					user_props = cJSON_CreateArray();
					if(user_props == NULL){
						return MOSQ_ERR_NOMEM;
					}
					cJSON_AddItemToObject(prop_json, "user-properties", user_props);
				}

				user_json = cJSON_CreateObject();
				if(user_json == NULL){
					return MOSQ_ERR_NOMEM;
				}
				cJSON_AddItemToArray(user_props, user_json);
				mosquitto_property_read_string_pair(prop, MQTT_PROP_USER_PROPERTY, &strname, &strvalue, false);
				if(strname == NULL || strvalue == NULL){
					free(strname);
					free(strvalue);
					return MOSQ_ERR_NOMEM;
				}

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


static void format_time_8601(const struct tm *ti, int ns, char *buf, size_t len)
{
	char c;

	strftime(buf, len, "%Y-%m-%dT%H:%M:%S.000000%z", ti);
	c = buf[strlen("2020-05-06T21:48:00.000000")];
	snprintf(&buf[strlen("2020-05-06T21:48:00.")], 9, "%06d", ns/1000);
	buf[strlen("2020-05-06T21:48:00.000000")] = c;
}


static int json_print(const struct mosquitto_message *message, const mosquitto_property *properties, const struct tm *ti, int ns, bool escaped, bool pretty)
{
	char buf[100];
	cJSON *root;
	cJSON *tmp;
	char *json_str;
	const char *return_parse_end;

	root = cJSON_CreateObject();
	if(root == NULL){
		return MOSQ_ERR_NOMEM;
	}

	format_time_8601(ti, ns, buf, sizeof(buf));

	if(cJSON_AddStringToObject(root, "tst", buf) == NULL
			|| cJSON_AddStringToObject(root, "topic", message->topic) == NULL
			|| cJSON_AddNumberToObject(root, "qos", message->qos) == NULL
			|| cJSON_AddBoolToObject(root, "retain", message->retain) == NULL
			|| cJSON_AddNumberToObject(root, "payloadlen", message->payloadlen) == NULL
			|| (message->qos > 0 && cJSON_AddNumberToObject(root, "mid", message->mid) == NULL)
			|| (properties && json_print_properties(root, properties))
			){

		cJSON_Delete(root);
		return MOSQ_ERR_NOMEM;
	}

	/* Payload */
	if(escaped){
		if(message->payload){
			tmp = cJSON_AddStringToObject(root, "payload", message->payload);
		}else{
			tmp = cJSON_AddNullToObject(root, "payload");
		}
		if(tmp == NULL){
			cJSON_Delete(root);
			return MOSQ_ERR_NOMEM;
		}
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
	if(json_str == NULL){
		return MOSQ_ERR_NOMEM;
	}

	fputs(json_str, stdout);
	free(json_str);

	return MOSQ_ERR_SUCCESS;
}


static void formatted_print_blank(struct fieldoptions *fopts)
{
	int i;
	for(i=0; i<fopts->field_width; i++){
		putchar(fopts->pad);
	}
}


#ifdef __STDC_IEC_559__


static int formatted_print_float(const unsigned char *payload, int payloadlen, char format, struct fieldoptions *fopts)
{
	float float_value;
	double value = 0.0;

	if(format == 'f'){
		if(sizeof(float_value) != payloadlen){
			return -1;
		}
		memcpy(&float_value, payload, sizeof(float_value));
		value = float_value;
	}else if(format == 'd'){
		if(sizeof(value) != payloadlen){
			return -1;
		}
		memcpy(&value, payload, sizeof(value));
	}

	if(fopts->field_width == 0){
		printf("%.*f", fopts->precision, value);
	}else{
		if(fopts->align == '-'){
			printf("%-*.*f", fopts->field_width, fopts->precision, value);
		}else{
			if(fopts->pad == '0'){
				printf("%0*.*f", fopts->field_width, fopts->precision, value);
			}else{
				printf("%*.*f", fopts->field_width, fopts->precision, value);
			}
		}
	}
	return 0;
}
#endif


static void formatted_print_int64(int64_t value, struct fieldoptions *fopts)
{
	if(fopts->field_width == 0){
		printf("%" PRId64, value);
	}else{
		if(fopts->align == '-'){
			printf("%-*" PRId64, fopts->field_width, value);
		}else{
			if(fopts->pad == '0'){
				printf("%0*" PRId64, fopts->field_width, value);
			}else{
				printf("%*" PRId64, fopts->field_width, value);
			}
		}
	}
}


static void formatted_print_int(int value, struct fieldoptions *fopts)
{
	if(fopts->field_width == 0){
		printf("%d", value);
	}else{
		if(fopts->align == '-'){
			printf("%-*d", fopts->field_width, value);
		}else{
			if(fopts->pad == '0'){
				printf("%0*d", fopts->field_width, value);
			}else{
				printf("%*d", fopts->field_width, value);
			}
		}
	}
}


static void formatted_print_str(const char *value, struct fieldoptions *fopts)
{
	if(fopts->field_width == 0 && fopts->precision == -1){
		fputs(value, stdout);
	}else{
		if(fopts->precision == -1){
			if(fopts->align == '-'){
				printf("%-*s", fopts->field_width, value);
			}else{
				printf("%*s", fopts->field_width, value);
			}
		}else if(fopts->field_width == 0){
			if(fopts->align == '-'){
				printf("%-.*s", fopts->precision, value);
			}else{
				printf("%.*s", fopts->precision, value);
			}
		}else{
			if(fopts->align == '-'){
				printf("%-*.*s", fopts->field_width, fopts->precision, value);
			}else{
				printf("%*.*s", fopts->field_width, fopts->precision, value);
			}
		}
	}
}


static void formatted_print_percent(const struct mosq_config *lcfg, const struct mosquitto_message *message, const mosquitto_property *properties, char format, struct fieldoptions *fopts)
{
	struct tm *ti = NULL;
	long ns = 0;
	char buf[100];
	int rc;
	uint8_t i8value;
	uint16_t i16value;
	uint32_t i32value;
	char *binvalue = NULL, *strname, *strvalue;
	const mosquitto_property *prop;


	switch(format){
		case '%':
			fputc('%', stdout);
			break;

		case 'A':
			if(mosquitto_property_read_int16(properties, MQTT_PROP_TOPIC_ALIAS, &i16value, false)){
				formatted_print_int(i16value, fopts);
			}else{
				formatted_print_blank(fopts);
			}
			break;

		case 'C':
			if(mosquitto_property_read_string(properties, MQTT_PROP_CONTENT_TYPE, &strvalue, false)){
				formatted_print_str(strvalue, fopts);
				free(strvalue);
			}else{
				formatted_print_blank(fopts);
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
				formatted_print_int((int)i32value, fopts);
			}else{
				formatted_print_blank(fopts);
			}
			break;

		case 'F':
			if(mosquitto_property_read_byte(properties, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, &i8value, false)){
				formatted_print_int(i8value, fopts);
			}else{
				formatted_print_blank(fopts);
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
				formatted_print_str(buf, fopts);
			}else{
				formatted_print_blank(fopts);
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
			formatted_print_int(message->payloadlen, fopts);
			break;

		case 'm':
			formatted_print_int(message->mid, fopts);
			break;

		case 'n':
			formatted_print_int64(lcfg->msg_count, fopts);
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
			write_payload(message->payload, message->payloadlen, 0, fopts);
			break;

		case 'q':
			fputc(message->qos + 48, stdout);
			break;

		case 'R':
			if(mosquitto_property_read_string(properties, MQTT_PROP_RESPONSE_TOPIC, &strvalue, false)){
				formatted_print_str(strvalue, fopts);
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
				formatted_print_int((int)i32value, fopts);
			}else{
				formatted_print_blank(fopts);
			}
			break;

		case 't':
			formatted_print_str(message->topic, fopts);
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
			write_payload(message->payload, message->payloadlen, 1, fopts);
			break;

		case 'X':
			write_payload(message->payload, message->payloadlen, 2, fopts);
			break;

#ifdef __STDC_IEC_559__
		case 'f':
			if(formatted_print_float(message->payload, message->payloadlen, 'f', fopts)){
				err_printf(lcfg, "requested float printing, but non-float data received");
			}
			break;

		case 'd':
			if(formatted_print_float(message->payload, message->payloadlen, 'd', fopts)){
				err_printf(lcfg, "requested double printing, but non-double data received");
			}
			break;
#endif
	}
}


static void formatted_print(const struct mosq_config *lcfg, const struct mosquitto_message *message, const mosquitto_property *properties)
{
	size_t len;
	struct tm *ti = NULL;
	long ns = 0;

	len = strlen(lcfg->format);

	for(size_t i=0; i<len; i++){
		if(lcfg->format[i] == '%'){
			struct fieldoptions fopts = {0, -1, ' ', '\0', ' '};
			if(i < len-1){
				i++;
				/* Optional alignment */
				if(lcfg->format[i] == '-'){
					fopts.align = lcfg->format[i];
					if(i < len-1){
						i++;
					}
				}
				/* "%-040p" is allowed by this combination of checks, but isn't
				 * a valid format specifier, the '0' will be ignored. */
				/* Optional zero padding */
				if(lcfg->format[i] == '0'){
					fopts.pad = '0';
					if(i < len-1){
						i++;
					}
				}
				/* Optional field width */
				while(i < len-1 && lcfg->format[i] >= '0' && lcfg->format[i] <= '9'){
					fopts.field_width *= 10;
					fopts.field_width += lcfg->format[i]-'0';
					i++;
				}
				/* Optional precision */
				if(lcfg->format[i] == '.'){
					if(i < len-1){
						i++;
						fopts.precision = 0;
						while(i < len-1 && lcfg->format[i] >= '0' && lcfg->format[i] <= '9'){
							fopts.precision *= 10;
							fopts.precision += lcfg->format[i]-'0';
							i++;
						}
					}
				}

				/* Optional hex field separator character */
				for(size_t j=0; j<sizeof(hexseplist); j++){
					if(lcfg->format[i] == hexseplist[j]){
						fopts.hexsepchar = hexseplist[j];
						i++;
						break;
					}
				}

				if(i < len){
					formatted_print_percent(lcfg, message, properties, lcfg->format[i], &fopts);
					//align, pad, field_width, precision, hexsepchar);
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

					char strf[3] = {0, 0, 0};
					strf[0] = '%';
					strf[1] = lcfg->format[i];
					strf[2] = 0;

					if(lcfg->format[i] == 'N'){
						printf("%09ld", ns);
					}else{
						char buf[100];
						if(strftime(buf, sizeof(buf), strf, ti) != 0){
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


static void rand_init(void)
{
#ifndef WIN32
	struct tm *ti = NULL;
	long ns;

	if(!get_time(&ti, &ns)){
		srandom((unsigned int)ns);
	}
#endif
}

#ifndef WIN32


static void watch_print(const struct mosquitto_message *message)
{
	struct watch_topic *item = NULL;

	HASH_FIND(hh, watch_items, message->topic, strlen(message->topic), item);
	if(item == NULL){
		item = calloc(1, sizeof(struct watch_topic));
		if(item == NULL){
			return;
		}
		item->line = watch_max++;
		item->topic = strdup(message->topic);
		if(item->topic == NULL){
			free(item);
			return;
		}
		HASH_ADD_KEYPTR(hh, watch_items, item->topic, strlen(item->topic), item);
	}
	printf("\e[%d;1H", item->line);
}
#endif


void print_message(struct mosq_config *lcfg, const struct mosquitto_message *message, const mosquitto_property *properties)
{
#ifdef WIN32
	unsigned int r = 0;
#else
	long r = 0;
#endif
	struct fieldoptions fopts = {0, 0, ' ', '\0', ' '};

#ifndef WIN32
	if(lcfg->watch){
		watch_print(message);
	}
#endif

	if(lcfg->random_filter < 10000){
#ifdef WIN32
		rand_s(&r);
#else
		/* coverity[dont_call] - we don't care about random() not being cryptographically secure here */
		r = random();
#endif
		if((long)(r%10000) >= lcfg->random_filter){
			return;
		}
	}
	if(lcfg->format){
		formatted_print(lcfg, message, properties);
	}else if(lcfg->verbose){
		if(message->payloadlen){
			printf("%s ", message->topic);
			write_payload(message->payload, message->payloadlen, false, &fopts);
			if(lcfg->eol){
				printf("\n");
			}
		}else{
			if(lcfg->eol){
				printf("%s (null)\n", message->topic);
			}
		}
		fflush(stdout);
	}else{
		if(message->payloadlen){
			write_payload(message->payload, message->payloadlen, false, &fopts);
			if(lcfg->eol){
				printf("\n");
			}
			fflush(stdout);
		}
	}
#ifndef WIN32
	if(lcfg->watch){
		printf("\e[%d;1H\n", watch_max-1);
	}
#endif
}


void output_init(struct mosq_config *lcfg)
{
	rand_init();
#ifndef WIN32
	if(lcfg->watch){
		printf("\e[2J\e[1;1H");
		printf("Broker: %s\n", lcfg->host);
	}
#endif
#ifdef WIN32
	/* Disable text translation so binary payloads aren't modified */
	(void)_setmode(_fileno(stdout), _O_BINARY);
#endif
}
