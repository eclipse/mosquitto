/*
Copyright (c) 2010-2021 Roger Light <roger@atchoo.org>

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

#ifndef MOSQUITTO_LIBCOMMON_TOPIC_H
#define MOSQUITTO_LIBCOMMON_TOPIC_H

/*
 * File: mosquitto/libcommon_topic.h
 *
 * This header contains functions and definitions for checking and manipulating topic strings.
 */
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Function: mosquitto_sub_topic_tokenise
 *
 * Tokenise a topic or subscription string into an array of strings
 * representing the topic hierarchy.
 *
 * For example:
 *
 *    subtopic: "a/deep/topic/hierarchy"
 *
 *    Would result in:
 *
 *       topics[0] = "a"
 *       topics[1] = "deep"
 *       topics[2] = "topic"
 *       topics[3] = "hierarchy"
 *
 *    and:
 *
 *    subtopic: "/a/deep/topic/hierarchy/"
 *
 *    Would result in:
 *
 *       topics[0] = NULL
 *       topics[1] = "a"
 *       topics[2] = "deep"
 *       topics[3] = "topic"
 *       topics[4] = "hierarchy"
 *
 * Parameters:
 *	subtopic - the subscription/topic to tokenise
 *	topics -   a pointer to store the array of strings
 *	count -    an int pointer to store the number of items in the topics array.
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS -        on success
 * 	MOSQ_ERR_NOMEM -          if an out of memory condition occurred.
 * 	MOSQ_ERR_MALFORMED_UTF8 - if the topic is not valid UTF-8
 *
 * Example:
 *
 * > char **topics;
 * > int topic_count;
 * > int i;
 * >
 * > mosquitto_sub_topic_tokenise("$SYS/broker/uptime", &topics, &topic_count);
 * >
 * > for(i=0; i<token_count; i++){
 * >     printf("%d: %s\n", i, topics[i]);
 * > }
 *
 * See Also:
 *	<mosquitto_sub_topic_tokens_free>
 */
libmosqcommon_EXPORT int mosquitto_sub_topic_tokenise(const char *subtopic, char ***topics, int *count);

/*
 * Function: mosquitto_sub_topic_tokens_free
 *
 * Free memory that was allocated in <mosquitto_sub_topic_tokenise>.
 *
 * Parameters:
 *	topics - pointer to string array.
 *	count - count of items in string array.
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 * 	MOSQ_ERR_INVAL -   if the input parameters were invalid.
 *
 * See Also:
 *	<mosquitto_sub_topic_tokenise>
 */
libmosqcommon_EXPORT int mosquitto_sub_topic_tokens_free(char ***topics, int count);

/*
 * Function: mosquitto_topic_matches_sub
 *
 * Check whether a topic matches a subscription.
 *
 * For example:
 *
 * foo/bar would match the subscription foo/# or +/bar
 * non/matching would not match the subscription non/+/+
 *
 * Parameters:
 *	sub - subscription string to check topic against.
 *	topic - topic to check.
 *	result - bool pointer to hold result. Will be set to true if the topic
 *	         matches the subscription.
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 * 	MOSQ_ERR_INVAL -   if the input parameters were invalid.
 */
libmosqcommon_EXPORT int mosquitto_topic_matches_sub(const char *sub, const char *topic, bool *result);

/*
 * Function: mosquitto_topic_matches_sub2
 *
 * Identical to <mosquitto_topic_matches_sub>. The sublen and topiclen
 * parameters are *IGNORED*.
 */
libmosqcommon_EXPORT int mosquitto_topic_matches_sub2(const char *sub, size_t sublen, const char *topic, size_t topiclen, bool *result);


/*
 * Function: mosquitto_topic_matches_sub_with_pattern
 *
 * Check whether a topic matches a subscription, with client id/username
 * pattern substitution.
 *
 * Any instances of a subscriptions hierarchy that are exactly %c or %u will be
 * replaced with the client id or username respectively.
 *
 * For example:
 *
 * mosquitto_topic_matches_sub_with_pattern("sensors/%c/temperature", "sensors/kitchen/temperature", "kitchen", NULL, &result)
 * -> this will match
 *
 * mosquitto_topic_matches_sub_with_pattern("sensors/%c/temperature", "sensors/bathroom/temperature", "kitchen", NULL, &result)
 * -> this will not match
 *
 * mosquitto_topic_matches_sub_with_pattern("sensors/%count/temperature", "sensors/kitchen/temperature", "kitchen", NULL, &result)
 * -> this will not match - the `%count` is not treated as a pattern
 *
 * mosquitto_topic_matches_sub_with_pattern("%c/%c/%u/%u", "kitchen/kitchen/bathroom/bathroom", "kitchen", "bathroom", &result)
 * -> this will match
 *
 * Parameters:
 *	sub - subscription string to check topic against.
 *	topic - topic to check.
 *	clientid - client id to substitute in patterns. If NULL, then any %c patterns will not match.
 *	username - username to substitute in patterns. If NULL, then any %u patterns will not match.
 *	result - bool pointer to hold result. Will be set to true if the topic
 *	         matches the subscription.
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 *	MOSQ_ERR_INVAL -   if the input parameters were invalid.
 */
libmosqcommon_EXPORT int mosquitto_topic_matches_sub_with_pattern(const char *sub, const char *topic, const char *clientid, const char *username, bool *result);


/*
 * Function: mosquitto_sub_matches_acl
 *
 * Check whether a subscription matches an ACL topic filter
 *
 * For example:
 *
 * The subscription $SYS/broker/# would match against the ACL $SYS/#
 * The subscription $SYS/broker/# would not match against the ACL $SYS/broker/uptime
 *
 * Parameters:
 *	acl - topic filter string to check sub against.
 *	sub - subscription topic to check.
 *	result - bool pointer to hold result. Will be set to true if the subscription
 *	         matches the acl.
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 * 	MOSQ_ERR_INVAL -   if the input parameters were invalid.
 */
libmosqcommon_EXPORT int mosquitto_sub_matches_acl(const char *acl, const char *sub, bool *result);


/*
 * Function: mosquitto_sub_matches_acl_with_pattern
 *
 * Check whether a subscription (a topic filter with wildcards) matches an ACL
 * (a topic filter with wildcards) , with client id/username pattern
 * substitution.
 *
 * Any instances of an ACL hierarchy that are exactly %c or %u will be
 * replaced with the client id or username respectively.
 *
 * For example:
 *
 * mosquitto_sub_matches_acl_with_pattern("sensors/%c/+", "sensors/kitchen/temperature", "kitchen", NULL, &result)
 * -> this will match
 *
 * mosquitto_sub_matches_acl_with_pattern("sensors/%c/+", "sensors/bathroom/temperature", "kitchen", NULL, &result)
 * -> this will not match
 *
 * mosquitto_sub_matches_acl_with_pattern("sensors/%count/+", "sensors/kitchen/temperature", "kitchen", NULL, &result)
 * -> this will not match - the `%count` is not treated as a pattern
 *
 * mosquitto_sub_matches_acl_with_pattern("%c/%c/%u/+", "kitchen/kitchen/bathroom/bathroom", "kitchen", "bathroom", &result)
 * -> this will match
 *
 * Parameters:
 *	acl - ACL topic filter string to check sub against.
 *	sub - subscription to check.
 *	clientid - client id to substitute in patterns. If NULL, then any %c patterns will not match.
 *	username - username to substitute in patterns. If NULL, then any %u patterns will not match.
 *	result - bool pointer to hold result. Will be set to true if the subscription
 *	         matches the ACL.
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS - on success
 *	MOSQ_ERR_INVAL -   if the input parameters were invalid.
 */
libmosqcommon_EXPORT int mosquitto_sub_matches_acl_with_pattern(const char *acl, const char *sub, const char *clientid, const char *username, bool *result);


/*
 * Function: mosquitto_pub_topic_check
 *
 * Check whether a topic to be used for publishing is valid.
 *
 * This searches for + or # in a topic and checks its length.
 *
 * This check is already carried out in <mosquitto_publish> and
 * <mosquitto_will_set>, there is no need to call it directly before them. It
 * may be useful if you wish to check the validity of a topic in advance of
 * making a connection for example.
 *
 * Parameters:
 *   topic - the topic to check
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS -        for a valid topic
 *   MOSQ_ERR_INVAL -          if the topic contains a + or a #, or if it is too long.
 *   MOSQ_ERR_MALFORMED_UTF8 - if topic is not valid UTF-8
 *
 * See Also:
 *   <mosquitto_sub_topic_check>
 */
libmosqcommon_EXPORT int mosquitto_pub_topic_check(const char *topic);

/*
 * Function: mosquitto_pub_topic_check2
 *
 * Check whether a topic to be used for publishing is valid.
 *
 * This searches for + or # in a topic and checks its length.
 *
 * This check is already carried out in <mosquitto_publish> and
 * <mosquitto_will_set>, there is no need to call it directly before them. It
 * may be useful if you wish to check the validity of a topic in advance of
 * making a connection for example.
 *
 * Parameters:
 *   topic - the topic to check
 *   topiclen - length of the topic in bytes
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS -        for a valid topic
 *   MOSQ_ERR_INVAL -          if the topic contains a + or a #, or if it is too long.
 *   MOSQ_ERR_MALFORMED_UTF8 - if topic is not valid UTF-8
 *
 * See Also:
 *   <mosquitto_sub_topic_check>
 */
libmosqcommon_EXPORT int mosquitto_pub_topic_check2(const char *topic, size_t topiclen);

/*
 * Function: mosquitto_sub_topic_check
 *
 * Check whether a topic to be used for subscribing is valid.
 *
 * This searches for + or # in a topic and checks that they aren't in invalid
 * positions, such as with foo/#/bar, foo/+bar or foo/bar#, and checks its
 * length.
 *
 * This check is already carried out in <mosquitto_subscribe> and
 * <mosquitto_unsubscribe>, there is no need to call it directly before them.
 * It may be useful if you wish to check the validity of a topic in advance of
 * making a connection for example.
 *
 * Parameters:
 *   topic - the topic to check
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS -        for a valid topic
 *   MOSQ_ERR_INVAL -          if the topic contains a + or a # that is in an
 *                             invalid position, or if it is too long.
 *   MOSQ_ERR_MALFORMED_UTF8 - if topic is not valid UTF-8
 *
 * See Also:
 *   <mosquitto_sub_topic_check>
 */
libmosqcommon_EXPORT int mosquitto_sub_topic_check(const char *topic);

/*
 * Function: mosquitto_sub_topic_check2
 *
 * Check whether a topic to be used for subscribing is valid.
 *
 * This searches for + or # in a topic and checks that they aren't in invalid
 * positions, such as with foo/#/bar, foo/+bar or foo/bar#, and checks its
 * length.
 *
 * This check is already carried out in <mosquitto_subscribe> and
 * <mosquitto_unsubscribe>, there is no need to call it directly before them.
 * It may be useful if you wish to check the validity of a topic in advance of
 * making a connection for example.
 *
 * Parameters:
 *   topic - the topic to check
 *   topiclen - the length in bytes of the topic
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS -        for a valid topic
 *   MOSQ_ERR_INVAL -          if the topic contains a + or a # that is in an
 *                             invalid position, or if it is too long.
 *   MOSQ_ERR_MALFORMED_UTF8 - if topic is not valid UTF-8
 *
 * See Also:
 *   <mosquitto_sub_topic_check>
 */
libmosqcommon_EXPORT int mosquitto_sub_topic_check2(const char *topic, size_t topiclen);

#ifdef __cplusplus
}
#endif

#endif
