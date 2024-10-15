/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

#include <string.h>

#ifdef WIN32
#  include <winsock2.h>
#  include <aclapi.h>
#  include <io.h>
#  include <lmcons.h>
#else
#  include <sys/stat.h>
#endif


#ifdef WITH_BROKER
#include "mosquitto_broker_internal.h"
#endif

#include "mosquitto.h"
#include "memory_mosq.h"
#include "net_mosq.h"
#include "send_mosq.h"
#include "time_mosq.h"
#include "tls_mosq.h"
#include "util_mosq.h"

/* Check that a topic used for publishing is valid.
 * Search for + or # in a topic. Return MOSQ_ERR_INVAL if found.
 * Also returns MOSQ_ERR_INVAL if the topic string is too long.
 * Returns MOSQ_ERR_SUCCESS if everything is fine.
 */
int mosquitto_pub_topic_check(const char *str)
{
	int len = 0;
#ifdef WITH_BROKER
	int hier_count = 0;
#endif

	if(str == NULL){
		return MOSQ_ERR_INVAL;
	}

	while(str && str[0]){
		if(str[0] == '+' || str[0] == '#'){
			return MOSQ_ERR_INVAL;
		}
#ifdef WITH_BROKER
		else if(str[0] == '/'){
			hier_count++;
		}
#endif
		len++;
		str = &str[1];
	}
	if(len == 0 || len > 65535) return MOSQ_ERR_INVAL;
#ifdef WITH_BROKER
	if(hier_count > TOPIC_HIERARCHY_LIMIT) return MOSQ_ERR_INVAL;
#endif

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_pub_topic_check2(const char *str, size_t len)
{
	size_t i;
#ifdef WITH_BROKER
	int hier_count = 0;
#endif

	if(str == NULL || len == 0 || len > 65535){
		return MOSQ_ERR_INVAL;
	}

	for(i=0; i<len; i++){
		if(str[i] == '+' || str[i] == '#'){
			return MOSQ_ERR_INVAL;
		}
#ifdef WITH_BROKER
		else if(str[i] == '/'){
			hier_count++;
		}
#endif
	}
#ifdef WITH_BROKER
	if(hier_count > TOPIC_HIERARCHY_LIMIT) return MOSQ_ERR_INVAL;
#endif

	return MOSQ_ERR_SUCCESS;
}

/* Check that a topic used for subscriptions is valid.
 * Search for + or # in a topic, check they aren't in invalid positions such as
 * foo/#/bar, foo/+bar or foo/bar#.
 * Return MOSQ_ERR_INVAL if invalid position found.
 * Also returns MOSQ_ERR_INVAL if the topic string is too long.
 * Returns MOSQ_ERR_SUCCESS if everything is fine.
 */
int mosquitto_sub_topic_check(const char *str)
{
	char c = '\0';
	int len = 0;
#ifdef WITH_BROKER
	int hier_count = 0;
#endif

	if(str == NULL){
		return MOSQ_ERR_INVAL;
	}

	while(str[0]){
		if(str[0] == '+'){
			if((c != '\0' && c != '/') || (str[1] != '\0' && str[1] != '/')){
				return MOSQ_ERR_INVAL;
			}
		}else if(str[0] == '#'){
			if((c != '\0' && c != '/')  || str[1] != '\0'){
				return MOSQ_ERR_INVAL;
			}
		}
#ifdef WITH_BROKER
		else if(str[0] == '/'){
			hier_count++;
		}
#endif
		len++;
		c = str[0];
		str = &str[1];
	}
	if(len == 0 || len > 65535) return MOSQ_ERR_INVAL;
#ifdef WITH_BROKER
	if(hier_count > TOPIC_HIERARCHY_LIMIT) return MOSQ_ERR_INVAL;
#endif

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_sub_topic_check2(const char *str, size_t len)
{
	char c = '\0';
	size_t i;
#ifdef WITH_BROKER
	int hier_count = 0;
#endif

	if(str == NULL || len == 0 || len > 65535){
		return MOSQ_ERR_INVAL;
	}

	for(i=0; i<len; i++){
		if(str[i] == '+'){
			if((c != '\0' && c != '/') || (i<len-1 && str[i+1] != '/')){
				return MOSQ_ERR_INVAL;
			}
		}else if(str[i] == '#'){
			if((c != '\0' && c != '/')  || i<len-1){
				return MOSQ_ERR_INVAL;
			}
		}
#ifdef WITH_BROKER
		else if(str[i] == '/'){
			hier_count++;
		}
#endif
		c = str[i];
	}
#ifdef WITH_BROKER
	if(hier_count > TOPIC_HIERARCHY_LIMIT) return MOSQ_ERR_INVAL;
#endif

	return MOSQ_ERR_SUCCESS;
}

/* Does a topic match a subscription? */
int mosquitto_topic_matches_sub(const char *sub, const char *topic, bool *result)
{
	size_t spos;

	if(!result) return MOSQ_ERR_INVAL;
	*result = false;

	if(!sub || !topic || sub[0] == 0 || topic[0] == 0){
		return MOSQ_ERR_INVAL;
	}

	if((sub[0] == '$' && topic[0] != '$')
			|| (topic[0] == '$' && sub[0] != '$')){

		return MOSQ_ERR_SUCCESS;
	}

	spos = 0;

	while(sub[0] != 0){
		if(topic[0] == '+' || topic[0] == '#'){
			return MOSQ_ERR_INVAL;
		}
		if(sub[0] != topic[0] || topic[0] == 0){ /* Check for wildcard matches */
			if(sub[0] == '+'){
				/* Check for bad "+foo" or "a/+foo" subscription */
				if(spos > 0 && sub[-1] != '/'){
					return MOSQ_ERR_INVAL;
				}
				/* Check for bad "foo+" or "foo+/a" subscription */
				if(sub[1] != 0 && sub[1] != '/'){
					return MOSQ_ERR_INVAL;
				}
				spos++;
				sub++;
				while(topic[0] != 0 && topic[0] != '/'){
					if(topic[0] == '+' || topic[0] == '#'){
						return MOSQ_ERR_INVAL;
					}
					topic++;
				}
				if(topic[0] == 0 && sub[0] == 0){
					*result = true;
					return MOSQ_ERR_SUCCESS;
				}
			}else if(sub[0] == '#'){
				/* Check for bad "foo#" subscription */
				if(spos > 0 && sub[-1] != '/'){
					return MOSQ_ERR_INVAL;
				}
				/* Check for # not the final character of the sub, e.g. "#foo" */
				if(sub[1] != 0){
					return MOSQ_ERR_INVAL;
				}else{
					while(topic[0] != 0){
						if(topic[0] == '+' || topic[0] == '#'){
							return MOSQ_ERR_INVAL;
						}
						topic++;
					}
					*result = true;
					return MOSQ_ERR_SUCCESS;
				}
			}else{
				/* Check for e.g. foo/bar matching foo/+/# */
				if(topic[0] == 0
						&& spos > 0
						&& sub[-1] == '+'
						&& sub[0] == '/'
						&& sub[1] == '#')
				{
					*result = true;
					return MOSQ_ERR_SUCCESS;
				}

				/* There is no match at this point, but is the sub invalid? */
				while(sub[0] != 0){
					if(sub[0] == '#' && sub[1] != 0){
						return MOSQ_ERR_INVAL;
					}
					spos++;
					sub++;
				}

				/* Valid input, but no match */
				return MOSQ_ERR_SUCCESS;
			}
		}else{
			/* sub[spos] == topic[tpos] */
			if(topic[1] == 0){
				/* Check for e.g. foo matching foo/# */
				if(sub[1] == '/'
						&& sub[2] == '#'
						&& sub[3] == 0){
					*result = true;
					return MOSQ_ERR_SUCCESS;
				}
			}
			spos++;
			sub++;
			topic++;
			if(sub[0] == 0 && topic[0] == 0){
				*result = true;
				return MOSQ_ERR_SUCCESS;
			}else if(topic[0] == 0 && sub[0] == '+' && sub[1] == 0){
				if(spos > 0 && sub[-1] != '/'){
					return MOSQ_ERR_INVAL;
				}
				spos++;
				sub++;
				*result = true;
				return MOSQ_ERR_SUCCESS;
			}
		}
	}
	if((topic[0] != 0 || sub[0] != 0)){
		*result = false;
	}
	while(topic[0] != 0){
		if(topic[0] == '+' || topic[0] == '#'){
			return MOSQ_ERR_INVAL;
		}
		topic++;
	}

	return MOSQ_ERR_SUCCESS;
}

/* Does a topic match a subscription? */
int mosquitto_topic_matches_sub2(const char *sub, size_t sublen, const char *topic, size_t topiclen, bool *result)
{
	size_t spos, tpos;

	if(!result) return MOSQ_ERR_INVAL;
	*result = false;

	if(!sub || !topic || !sublen || !topiclen){
		return MOSQ_ERR_INVAL;
	}

	if((sub[0] == '$' && topic[0] != '$')
			|| (topic[0] == '$' && sub[0] != '$')){

		return MOSQ_ERR_SUCCESS;
	}

	spos = 0;
	tpos = 0;

	while(spos < sublen){
		if(tpos < topiclen && (topic[tpos] == '+' || topic[tpos] == '#')){
			return MOSQ_ERR_INVAL;
		}
		if(tpos == topiclen || sub[spos] != topic[tpos]){
			if(sub[spos] == '+'){
				/* Check for bad "+foo" or "a/+foo" subscription */
				if(spos > 0 && sub[spos-1] != '/'){
					return MOSQ_ERR_INVAL;
				}
				/* Check for bad "foo+" or "foo+/a" subscription */
				if(spos+1 < sublen && sub[spos+1] != '/'){
					return MOSQ_ERR_INVAL;
				}
				spos++;
				while(tpos < topiclen && topic[tpos] != '/'){
					if(topic[tpos] == '+' || topic[tpos] == '#'){
						return MOSQ_ERR_INVAL;
					}
					tpos++;
				}
				if(tpos == topiclen && spos == sublen){
					*result = true;
					return MOSQ_ERR_SUCCESS;
				}
			}else if(sub[spos] == '#'){
				/* Check for bad "foo#" subscription */
				if(spos > 0 && sub[spos-1] != '/'){
					return MOSQ_ERR_INVAL;
				}
				/* Check for # not the final character of the sub, e.g. "#foo" */
				if(spos+1 < sublen){
					return MOSQ_ERR_INVAL;
				}else{
					while(tpos < topiclen){
						if(topic[tpos] == '+' || topic[tpos] == '#'){
							return MOSQ_ERR_INVAL;
						}
						tpos++;
					}
					*result = true;
					return MOSQ_ERR_SUCCESS;
				}
			}else{
				/* Check for e.g. foo/bar matching foo/+/# */
				if(tpos == topiclen
						&& spos > 0
						&& sub[spos-1] == '+'
						&& sub[spos] == '/'
						&& spos+1 < sublen
						&& sub[spos+1] == '#')
				{
					*result = true;
					return MOSQ_ERR_SUCCESS;
				}

				/* There is no match at this point, but is the sub invalid? */
				while(spos < sublen){
					if(sub[spos] == '#' && spos+1 < sublen){
						return MOSQ_ERR_INVAL;
					}
					spos++;
				}

				/* Valid input, but no match */
				return MOSQ_ERR_SUCCESS;
			}
		}else{
			/* sub[spos] == topic[tpos] */
			if(tpos+1 == topiclen){
				/* Check for e.g. foo matching foo/# */
				if(spos+3 == sublen
						&& sub[spos+1] == '/'
						&& sub[spos+2] == '#'){
					*result = true;
					return MOSQ_ERR_SUCCESS;
				}
			}
			spos++;
			tpos++;
			if(spos == sublen && tpos == topiclen){
				*result = true;
				return MOSQ_ERR_SUCCESS;
			}else if(tpos == topiclen && sub[spos] == '+' && spos+1 == sublen){
				if(spos > 0 && sub[spos-1] != '/'){
					return MOSQ_ERR_INVAL;
				}
				spos++;
				*result = true;
				return MOSQ_ERR_SUCCESS;
			}
		}
	}
	if(tpos < topiclen || spos < sublen){
		*result = false;
	}
	while(tpos < topiclen){
		if(topic[tpos] == '+' || topic[tpos] == '#'){
			return MOSQ_ERR_INVAL;
		}
		tpos++;
	}

	return MOSQ_ERR_SUCCESS;
}
