#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "mqtt_protocol.h"
#include "property_mosq.h"
#include "packet_mosq.h"

static void check_count(mosquitto_property *proplist, int expected)
{
	mosquitto_property *p;
	int count;

	if(proplist == NULL){
		CU_ASSERT_EQUAL(expected, 0);
		return;
	}

	p = proplist;
	count = 0;
	while(p){
		count++;
		p = p->next;
	}
	CU_ASSERT_EQUAL(count, expected);
}

/* ========================================================================
 * BAD IDENTIFIER
 * ======================================================================== */

static void bad_add_byte_helper(int identifier)
{
	mosquitto_property *proplist = NULL;
	int rc;

	rc = mosquitto_property_add_byte(&proplist, identifier, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_PTR_NULL(proplist);
}

static void bad_add_int16_helper(int identifier)
{
	mosquitto_property *proplist = NULL;
	int rc;

	rc = mosquitto_property_add_int16(&proplist, identifier, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_PTR_NULL(proplist);
}

static void bad_add_int32_helper(int identifier)
{
	mosquitto_property *proplist = NULL;
	int rc;

	rc = mosquitto_property_add_int32(&proplist, identifier, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_PTR_NULL(proplist);
}

static void bad_add_varint_helper(int identifier)
{
	mosquitto_property *proplist = NULL;
	int rc;

	rc = mosquitto_property_add_varint(&proplist, identifier, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_PTR_NULL(proplist);
}

static void bad_add_binary_helper(int identifier)
{
	mosquitto_property *proplist = NULL;
	int rc;

	rc = mosquitto_property_add_binary(&proplist, identifier, "test", 4);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_PTR_NULL(proplist);
}

static void bad_add_string_helper(int identifier)
{
	mosquitto_property *proplist = NULL;
	int rc;

	rc = mosquitto_property_add_string(&proplist, identifier, "test");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_PTR_NULL(proplist);
}

static void bad_add_string_pair_helper(int identifier)
{
	mosquitto_property *proplist = NULL;
	int rc;

	rc = mosquitto_property_add_string_pair(&proplist, identifier, "key", "value");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_PTR_NULL(proplist);
}

static void TEST_add_bad_byte(void)
{
	bad_add_byte_helper(MQTT_PROP_MESSAGE_EXPIRY_INTERVAL);
	bad_add_byte_helper(MQTT_PROP_CONTENT_TYPE);
	bad_add_byte_helper(MQTT_PROP_RESPONSE_TOPIC);
	bad_add_byte_helper(MQTT_PROP_CORRELATION_DATA);
	bad_add_byte_helper(MQTT_PROP_SUBSCRIPTION_IDENTIFIER);
	bad_add_byte_helper(MQTT_PROP_SESSION_EXPIRY_INTERVAL);
	bad_add_byte_helper(MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER);
	bad_add_byte_helper(MQTT_PROP_SERVER_KEEP_ALIVE);
	bad_add_byte_helper(MQTT_PROP_AUTHENTICATION_METHOD);
	bad_add_byte_helper(MQTT_PROP_AUTHENTICATION_DATA);
	bad_add_byte_helper(MQTT_PROP_WILL_DELAY_INTERVAL);
	bad_add_byte_helper(MQTT_PROP_RESPONSE_INFORMATION);
	bad_add_byte_helper(MQTT_PROP_SERVER_REFERENCE);
	bad_add_byte_helper(MQTT_PROP_REASON_STRING);
	bad_add_byte_helper(MQTT_PROP_RECEIVE_MAXIMUM);
	bad_add_byte_helper(MQTT_PROP_TOPIC_ALIAS_MAXIMUM);
	bad_add_byte_helper(MQTT_PROP_TOPIC_ALIAS);
	bad_add_byte_helper(MQTT_PROP_USER_PROPERTY);
	bad_add_byte_helper(MQTT_PROP_MAXIMUM_PACKET_SIZE);
}

static void TEST_add_bad_int16(void)
{
	bad_add_int16_helper(MQTT_PROP_PAYLOAD_FORMAT_INDICATOR);
	bad_add_int16_helper(MQTT_PROP_MESSAGE_EXPIRY_INTERVAL);
	bad_add_int16_helper(MQTT_PROP_CONTENT_TYPE);
	bad_add_int16_helper(MQTT_PROP_RESPONSE_TOPIC);
	bad_add_int16_helper(MQTT_PROP_CORRELATION_DATA);
	bad_add_int16_helper(MQTT_PROP_SUBSCRIPTION_IDENTIFIER);
	bad_add_int16_helper(MQTT_PROP_SESSION_EXPIRY_INTERVAL);
	bad_add_int16_helper(MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER);
	bad_add_int16_helper(MQTT_PROP_AUTHENTICATION_METHOD);
	bad_add_int16_helper(MQTT_PROP_AUTHENTICATION_DATA);
	bad_add_int16_helper(MQTT_PROP_REQUEST_PROBLEM_INFORMATION);
	bad_add_int16_helper(MQTT_PROP_WILL_DELAY_INTERVAL);
	bad_add_int16_helper(MQTT_PROP_REQUEST_RESPONSE_INFORMATION);
	bad_add_int16_helper(MQTT_PROP_RESPONSE_INFORMATION);
	bad_add_int16_helper(MQTT_PROP_SERVER_REFERENCE);
	bad_add_int16_helper(MQTT_PROP_REASON_STRING);
	bad_add_int16_helper(MQTT_PROP_MAXIMUM_QOS);
	bad_add_int16_helper(MQTT_PROP_RETAIN_AVAILABLE);
	bad_add_int16_helper(MQTT_PROP_USER_PROPERTY);
	bad_add_int16_helper(MQTT_PROP_MAXIMUM_PACKET_SIZE);
	bad_add_int16_helper(MQTT_PROP_WILDCARD_SUB_AVAILABLE);
	bad_add_int16_helper(MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE);
	bad_add_int16_helper(MQTT_PROP_SHARED_SUB_AVAILABLE);
}

static void TEST_add_bad_int32(void)
{
	bad_add_int32_helper(MQTT_PROP_PAYLOAD_FORMAT_INDICATOR);
	bad_add_int32_helper(MQTT_PROP_CONTENT_TYPE);
	bad_add_int32_helper(MQTT_PROP_RESPONSE_TOPIC);
	bad_add_int32_helper(MQTT_PROP_CORRELATION_DATA);
	bad_add_int32_helper(MQTT_PROP_SUBSCRIPTION_IDENTIFIER);
	bad_add_int32_helper(MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER);
	bad_add_int32_helper(MQTT_PROP_SERVER_KEEP_ALIVE);
	bad_add_int32_helper(MQTT_PROP_AUTHENTICATION_METHOD);
	bad_add_int32_helper(MQTT_PROP_AUTHENTICATION_DATA);
	bad_add_int32_helper(MQTT_PROP_REQUEST_PROBLEM_INFORMATION);
	bad_add_int32_helper(MQTT_PROP_REQUEST_RESPONSE_INFORMATION);
	bad_add_int32_helper(MQTT_PROP_RESPONSE_INFORMATION);
	bad_add_int32_helper(MQTT_PROP_SERVER_REFERENCE);
	bad_add_int32_helper(MQTT_PROP_REASON_STRING);
	bad_add_int32_helper(MQTT_PROP_RECEIVE_MAXIMUM);
	bad_add_int32_helper(MQTT_PROP_TOPIC_ALIAS_MAXIMUM);
	bad_add_int32_helper(MQTT_PROP_TOPIC_ALIAS);
	bad_add_int32_helper(MQTT_PROP_MAXIMUM_QOS);
	bad_add_int32_helper(MQTT_PROP_RETAIN_AVAILABLE);
	bad_add_int32_helper(MQTT_PROP_USER_PROPERTY);
	bad_add_int32_helper(MQTT_PROP_WILDCARD_SUB_AVAILABLE);
	bad_add_int32_helper(MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE);
	bad_add_int32_helper(MQTT_PROP_SHARED_SUB_AVAILABLE);
}

static void TEST_add_bad_varint(void)
{
	bad_add_varint_helper(MQTT_PROP_PAYLOAD_FORMAT_INDICATOR);
	bad_add_varint_helper(MQTT_PROP_MESSAGE_EXPIRY_INTERVAL);
	bad_add_varint_helper(MQTT_PROP_CONTENT_TYPE);
	bad_add_varint_helper(MQTT_PROP_RESPONSE_TOPIC);
	bad_add_varint_helper(MQTT_PROP_CORRELATION_DATA);
	bad_add_varint_helper(MQTT_PROP_SESSION_EXPIRY_INTERVAL);
	bad_add_varint_helper(MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER);
	bad_add_varint_helper(MQTT_PROP_SERVER_KEEP_ALIVE);
	bad_add_varint_helper(MQTT_PROP_AUTHENTICATION_METHOD);
	bad_add_varint_helper(MQTT_PROP_AUTHENTICATION_DATA);
	bad_add_varint_helper(MQTT_PROP_REQUEST_PROBLEM_INFORMATION);
	bad_add_varint_helper(MQTT_PROP_WILL_DELAY_INTERVAL);
	bad_add_varint_helper(MQTT_PROP_REQUEST_RESPONSE_INFORMATION);
	bad_add_varint_helper(MQTT_PROP_RESPONSE_INFORMATION);
	bad_add_varint_helper(MQTT_PROP_SERVER_REFERENCE);
	bad_add_varint_helper(MQTT_PROP_REASON_STRING);
	bad_add_varint_helper(MQTT_PROP_RECEIVE_MAXIMUM);
	bad_add_varint_helper(MQTT_PROP_TOPIC_ALIAS_MAXIMUM);
	bad_add_varint_helper(MQTT_PROP_TOPIC_ALIAS);
	bad_add_varint_helper(MQTT_PROP_MAXIMUM_QOS);
	bad_add_varint_helper(MQTT_PROP_RETAIN_AVAILABLE);
	bad_add_varint_helper(MQTT_PROP_USER_PROPERTY);
	bad_add_varint_helper(MQTT_PROP_MAXIMUM_PACKET_SIZE);
	bad_add_varint_helper(MQTT_PROP_WILDCARD_SUB_AVAILABLE);
	bad_add_varint_helper(MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE);
	bad_add_varint_helper(MQTT_PROP_SHARED_SUB_AVAILABLE);
}

static void TEST_add_bad_binary(void)
{
	bad_add_binary_helper(MQTT_PROP_PAYLOAD_FORMAT_INDICATOR);
	bad_add_binary_helper(MQTT_PROP_MESSAGE_EXPIRY_INTERVAL);
	bad_add_binary_helper(MQTT_PROP_CONTENT_TYPE);
	bad_add_binary_helper(MQTT_PROP_RESPONSE_TOPIC);
	bad_add_binary_helper(MQTT_PROP_SUBSCRIPTION_IDENTIFIER);
	bad_add_binary_helper(MQTT_PROP_SESSION_EXPIRY_INTERVAL);
	bad_add_binary_helper(MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER);
	bad_add_binary_helper(MQTT_PROP_SERVER_KEEP_ALIVE);
	bad_add_binary_helper(MQTT_PROP_AUTHENTICATION_METHOD);
	bad_add_binary_helper(MQTT_PROP_REQUEST_PROBLEM_INFORMATION);
	bad_add_binary_helper(MQTT_PROP_WILL_DELAY_INTERVAL);
	bad_add_binary_helper(MQTT_PROP_REQUEST_RESPONSE_INFORMATION);
	bad_add_binary_helper(MQTT_PROP_RESPONSE_INFORMATION);
	bad_add_binary_helper(MQTT_PROP_SERVER_REFERENCE);
	bad_add_binary_helper(MQTT_PROP_REASON_STRING);
	bad_add_binary_helper(MQTT_PROP_RECEIVE_MAXIMUM);
	bad_add_binary_helper(MQTT_PROP_TOPIC_ALIAS_MAXIMUM);
	bad_add_binary_helper(MQTT_PROP_TOPIC_ALIAS);
	bad_add_binary_helper(MQTT_PROP_MAXIMUM_QOS);
	bad_add_binary_helper(MQTT_PROP_RETAIN_AVAILABLE);
	bad_add_binary_helper(MQTT_PROP_USER_PROPERTY);
	bad_add_binary_helper(MQTT_PROP_MAXIMUM_PACKET_SIZE);
	bad_add_binary_helper(MQTT_PROP_WILDCARD_SUB_AVAILABLE);
	bad_add_binary_helper(MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE);
	bad_add_binary_helper(MQTT_PROP_SHARED_SUB_AVAILABLE);
}

static void TEST_add_bad_string(void)
{
	bad_add_string_helper(MQTT_PROP_PAYLOAD_FORMAT_INDICATOR);
	bad_add_string_helper(MQTT_PROP_MESSAGE_EXPIRY_INTERVAL);
	bad_add_string_helper(MQTT_PROP_CORRELATION_DATA);
	bad_add_string_helper(MQTT_PROP_SUBSCRIPTION_IDENTIFIER);
	bad_add_string_helper(MQTT_PROP_SESSION_EXPIRY_INTERVAL);
	bad_add_string_helper(MQTT_PROP_SERVER_KEEP_ALIVE);
	bad_add_string_helper(MQTT_PROP_AUTHENTICATION_DATA);
	bad_add_string_helper(MQTT_PROP_REQUEST_PROBLEM_INFORMATION);
	bad_add_string_helper(MQTT_PROP_WILL_DELAY_INTERVAL);
	bad_add_string_helper(MQTT_PROP_REQUEST_RESPONSE_INFORMATION);
	bad_add_string_helper(MQTT_PROP_RECEIVE_MAXIMUM);
	bad_add_string_helper(MQTT_PROP_TOPIC_ALIAS_MAXIMUM);
	bad_add_string_helper(MQTT_PROP_TOPIC_ALIAS);
	bad_add_string_helper(MQTT_PROP_MAXIMUM_QOS);
	bad_add_string_helper(MQTT_PROP_RETAIN_AVAILABLE);
	bad_add_string_helper(MQTT_PROP_USER_PROPERTY);
	bad_add_string_helper(MQTT_PROP_MAXIMUM_PACKET_SIZE);
	bad_add_string_helper(MQTT_PROP_WILDCARD_SUB_AVAILABLE);
	bad_add_string_helper(MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE);
	bad_add_string_helper(MQTT_PROP_SHARED_SUB_AVAILABLE);
}

static void TEST_add_bad_string_pair(void)
{
	bad_add_string_pair_helper(MQTT_PROP_PAYLOAD_FORMAT_INDICATOR);
	bad_add_string_pair_helper(MQTT_PROP_MESSAGE_EXPIRY_INTERVAL);
	bad_add_string_pair_helper(MQTT_PROP_CONTENT_TYPE);
	bad_add_string_pair_helper(MQTT_PROP_RESPONSE_TOPIC);
	bad_add_string_pair_helper(MQTT_PROP_CORRELATION_DATA);
	bad_add_string_pair_helper(MQTT_PROP_SUBSCRIPTION_IDENTIFIER);
	bad_add_string_pair_helper(MQTT_PROP_SESSION_EXPIRY_INTERVAL);
	bad_add_string_pair_helper(MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER);
	bad_add_string_pair_helper(MQTT_PROP_SERVER_KEEP_ALIVE);
	bad_add_string_pair_helper(MQTT_PROP_AUTHENTICATION_METHOD);
	bad_add_string_pair_helper(MQTT_PROP_AUTHENTICATION_DATA);
	bad_add_string_pair_helper(MQTT_PROP_REQUEST_PROBLEM_INFORMATION);
	bad_add_string_pair_helper(MQTT_PROP_WILL_DELAY_INTERVAL);
	bad_add_string_pair_helper(MQTT_PROP_REQUEST_RESPONSE_INFORMATION);
	bad_add_string_pair_helper(MQTT_PROP_RESPONSE_INFORMATION);
	bad_add_string_pair_helper(MQTT_PROP_SERVER_REFERENCE);
	bad_add_string_pair_helper(MQTT_PROP_REASON_STRING);
	bad_add_string_pair_helper(MQTT_PROP_RECEIVE_MAXIMUM);
	bad_add_string_pair_helper(MQTT_PROP_TOPIC_ALIAS_MAXIMUM);
	bad_add_string_pair_helper(MQTT_PROP_TOPIC_ALIAS);
	bad_add_string_pair_helper(MQTT_PROP_MAXIMUM_QOS);
	bad_add_string_pair_helper(MQTT_PROP_RETAIN_AVAILABLE);
	bad_add_string_pair_helper(MQTT_PROP_MAXIMUM_PACKET_SIZE);
	bad_add_string_pair_helper(MQTT_PROP_WILDCARD_SUB_AVAILABLE);
	bad_add_string_pair_helper(MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE);
	bad_add_string_pair_helper(MQTT_PROP_SHARED_SUB_AVAILABLE);
}

/* ========================================================================
 * SINGLE ADD
 * ======================================================================== */

static void single_add_byte_helper(int identifier)
{
	mosquitto_property *proplist = NULL;
	int rc;

	rc = mosquitto_property_add_byte(&proplist, identifier, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	if(proplist){
		CU_ASSERT_EQUAL(proplist->identifier, identifier);
		CU_ASSERT_EQUAL(proplist->value.i8, 1);
		CU_ASSERT_PTR_NULL(proplist->next);

		mosquitto_property_free_all(&proplist);
	}
}

static void single_add_int16_helper(int identifier)
{
	mosquitto_property *proplist = NULL;
	int rc;

	rc = mosquitto_property_add_int16(&proplist, identifier, 11234);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	if(proplist){
		CU_ASSERT_EQUAL(proplist->identifier, identifier);
		CU_ASSERT_EQUAL(proplist->value.i16, 11234);
		CU_ASSERT_PTR_NULL(proplist->next);

		mosquitto_property_free_all(&proplist);
	}
}

static void single_add_int32_helper(int identifier)
{
	mosquitto_property *proplist = NULL;
	int rc;

	rc = mosquitto_property_add_int32(&proplist, identifier, 765432);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	if(proplist){
		CU_ASSERT_EQUAL(proplist->identifier, identifier);
		CU_ASSERT_EQUAL(proplist->value.i32, 765432);
		CU_ASSERT_PTR_NULL(proplist->next);

		mosquitto_property_free_all(&proplist);
	}
}

static void single_add_varint_helper(int identifier)
{
	mosquitto_property *proplist = NULL;
	int rc;

	rc = mosquitto_property_add_varint(&proplist, identifier, 139123999);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	if(proplist){
		CU_ASSERT_EQUAL(proplist->identifier, identifier);
		CU_ASSERT_EQUAL(proplist->value.varint, 139123999);
		CU_ASSERT_PTR_NULL(proplist->next);

		mosquitto_property_free_all(&proplist);
	}
}

static void single_add_binary_helper(int identifier)
{
	mosquitto_property *proplist = NULL;
	int rc;

	rc = mosquitto_property_add_binary(&proplist, identifier, "test", 4);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	if(proplist){
		CU_ASSERT_EQUAL(proplist->identifier, identifier);
		CU_ASSERT_EQUAL(proplist->value.bin.len, 4);
		CU_ASSERT_NSTRING_EQUAL(proplist->value.bin.v, "test", 4);
		CU_ASSERT_PTR_NULL(proplist->next);

		mosquitto_property_free_all(&proplist);
	}
}

static void single_add_string_helper(int identifier)
{
	mosquitto_property *proplist = NULL;
	int rc;

	rc = mosquitto_property_add_string(&proplist, identifier, "string");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	if(proplist){
		CU_ASSERT_EQUAL(proplist->identifier, identifier);
		CU_ASSERT_STRING_EQUAL(proplist->value.s.v, "string");
		CU_ASSERT_EQUAL(proplist->value.s.len, strlen("string"));
		CU_ASSERT_PTR_NULL(proplist->next);

		mosquitto_property_free_all(&proplist);
	}
}

static void single_add_string_pair_helper(int identifier)
{
	mosquitto_property *proplist = NULL;
	int rc;

	rc = mosquitto_property_add_string_pair(&proplist, identifier, "key", "value");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	if(proplist){
		CU_ASSERT_EQUAL(proplist->identifier, identifier);
		CU_ASSERT_STRING_EQUAL(proplist->name.v, "key");
		CU_ASSERT_EQUAL(proplist->name.len, strlen("key"));
		CU_ASSERT_STRING_EQUAL(proplist->value.s.v, "value");
		CU_ASSERT_EQUAL(proplist->value.s.len, strlen("value"));
		CU_ASSERT_PTR_NULL(proplist->next);

		mosquitto_property_free_all(&proplist);
	}
}

static void TEST_add_single_byte(void)
{
	single_add_byte_helper(MQTT_PROP_PAYLOAD_FORMAT_INDICATOR);
	single_add_byte_helper(MQTT_PROP_REQUEST_PROBLEM_INFORMATION);
	single_add_byte_helper(MQTT_PROP_REQUEST_RESPONSE_INFORMATION);
	single_add_byte_helper(MQTT_PROP_MAXIMUM_QOS);
	single_add_byte_helper(MQTT_PROP_RETAIN_AVAILABLE);
	single_add_byte_helper(MQTT_PROP_WILDCARD_SUB_AVAILABLE);
	single_add_byte_helper(MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE);
	single_add_byte_helper(MQTT_PROP_SHARED_SUB_AVAILABLE);
}

static void TEST_add_single_int16(void)
{
	single_add_int16_helper(MQTT_PROP_SERVER_KEEP_ALIVE);
	single_add_int16_helper(MQTT_PROP_RECEIVE_MAXIMUM);
	single_add_int16_helper(MQTT_PROP_TOPIC_ALIAS_MAXIMUM);
	single_add_int16_helper(MQTT_PROP_TOPIC_ALIAS);
}

static void TEST_add_single_int32(void)
{
	single_add_int32_helper(MQTT_PROP_MESSAGE_EXPIRY_INTERVAL);
	single_add_int32_helper(MQTT_PROP_SESSION_EXPIRY_INTERVAL);
	single_add_int32_helper(MQTT_PROP_WILL_DELAY_INTERVAL);
	single_add_int32_helper(MQTT_PROP_MAXIMUM_PACKET_SIZE);
}

static void TEST_add_single_varint(void)
{
	single_add_varint_helper(MQTT_PROP_SUBSCRIPTION_IDENTIFIER);
}

static void TEST_add_single_binary(void)
{
	single_add_binary_helper(MQTT_PROP_CORRELATION_DATA);
	single_add_binary_helper(MQTT_PROP_AUTHENTICATION_DATA);
}

static void TEST_add_single_string(void)
{
	single_add_string_helper(MQTT_PROP_CONTENT_TYPE);
	single_add_string_helper(MQTT_PROP_RESPONSE_TOPIC);
	single_add_string_helper(MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER);
	single_add_string_helper(MQTT_PROP_AUTHENTICATION_METHOD);
	single_add_string_helper(MQTT_PROP_RESPONSE_INFORMATION);
	single_add_string_helper(MQTT_PROP_SERVER_REFERENCE);
	single_add_string_helper(MQTT_PROP_REASON_STRING);
}

static void TEST_add_single_string_pair(void)
{
	single_add_string_pair_helper(MQTT_PROP_USER_PROPERTY);
}

/* ========================================================================
 * ADD ALL PROPERTIES FOR A COMMAND
 * ======================================================================== */

static void TEST_add_all_connect(void)
{
	mosquitto_property *proplist = NULL;
	int rc;

	rc = mosquitto_property_add_int32(&proplist, MQTT_PROP_SESSION_EXPIRY_INTERVAL, 86400);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_string(&proplist, MQTT_PROP_AUTHENTICATION_METHOD, "basic");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_binary(&proplist, MQTT_PROP_AUTHENTICATION_DATA, "password", strlen("password"));
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_byte(&proplist, MQTT_PROP_REQUEST_PROBLEM_INFORMATION, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_byte(&proplist, MQTT_PROP_REQUEST_RESPONSE_INFORMATION, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_int16(&proplist, MQTT_PROP_RECEIVE_MAXIMUM, 1024);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_int16(&proplist, MQTT_PROP_TOPIC_ALIAS_MAXIMUM, 64);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_string_pair(&proplist, MQTT_PROP_USER_PROPERTY, "user-agent", "mosquitto/test");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_int32(&proplist, MQTT_PROP_MAXIMUM_PACKET_SIZE, 200000000);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);

	check_count(proplist, 9);

	mosquitto_property_free_all(&proplist);
}


static void TEST_add_all_connack(void)
{
	mosquitto_property *proplist = NULL;
	int rc;

	rc = mosquitto_property_add_int32(&proplist, MQTT_PROP_SESSION_EXPIRY_INTERVAL, 86400);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_string(&proplist, MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER, "clientid");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_int16(&proplist, MQTT_PROP_SERVER_KEEP_ALIVE, 900);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_string(&proplist, MQTT_PROP_AUTHENTICATION_METHOD, "basic");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_binary(&proplist, MQTT_PROP_AUTHENTICATION_DATA, "password", strlen("password"));
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_string(&proplist, MQTT_PROP_RESPONSE_INFORMATION, "response");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_string(&proplist, MQTT_PROP_SERVER_REFERENCE, "localhost");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_string(&proplist, MQTT_PROP_REASON_STRING, "reason");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_int16(&proplist, MQTT_PROP_RECEIVE_MAXIMUM, 1024);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_int16(&proplist, MQTT_PROP_TOPIC_ALIAS_MAXIMUM, 64);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_byte(&proplist, MQTT_PROP_MAXIMUM_QOS, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_byte(&proplist, MQTT_PROP_RETAIN_AVAILABLE, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_string_pair(&proplist, MQTT_PROP_USER_PROPERTY, "user-agent", "mosquitto/test");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_int32(&proplist, MQTT_PROP_MAXIMUM_PACKET_SIZE, 200000000);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_byte(&proplist, MQTT_PROP_WILDCARD_SUB_AVAILABLE, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_byte(&proplist, MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	rc = mosquitto_property_add_byte(&proplist, MQTT_PROP_SHARED_SUB_AVAILABLE, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);

	check_count(proplist, 17);

	mosquitto_property_free_all(&proplist);
}


static void TEST_check_length(void)
{
	mosquitto_property *proplist = NULL;
	int rc;
	unsigned int len;
	unsigned int varbytes;
	unsigned int i;

	len = property__get_remaining_length(proplist);
	CU_ASSERT_EQUAL(len, 1);

	for(i=1; i<10000; i++){
		rc = mosquitto_property_add_byte(&proplist, MQTT_PROP_SHARED_SUB_AVAILABLE, 0);
		CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
		CU_ASSERT_PTR_NOT_NULL(proplist);
		if(proplist){
			len = property__get_remaining_length(proplist);
			if(i < 64){
				varbytes = 1;
			}else if(i < 8192){
				varbytes = 2;
			}else{
				varbytes = 3;
			}
			CU_ASSERT_EQUAL(len, varbytes+2*i);
		}else{
			break;
		}
	}
	mosquitto_property_free_all(&proplist);
}

static void TEST_remove_single(void)
{
	mosquitto_property *proplist = NULL, *property;
	int rc;
	unsigned int len;

	len = property__get_remaining_length(proplist);
	CU_ASSERT_EQUAL(len, 1);

	for(int i=1; i<10; i++){
		rc = mosquitto_property_add_byte(&proplist, MQTT_PROP_SHARED_SUB_AVAILABLE, 0);
		CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
		CU_ASSERT_PTR_NOT_NULL(proplist);
	}
	check_count(proplist, 9);

	/* Remove end item */
	property = proplist;
	while(property && property->next){
		property = property->next;
	}

	rc = mosquitto_property_remove(&proplist, property);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	mosquitto_property_free_all(&property);

	check_count(proplist, 8);

	/* Remove middle item */
	property = proplist;
	for(int i=0; i<4; i++){
		property = property->next;
	}
	rc = mosquitto_property_remove(&proplist, property);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	mosquitto_property_free_all(&property);

	check_count(proplist, 7);

	/* Remove front item */
	property = proplist;
	rc = mosquitto_property_remove(&proplist, property);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_EQUAL(proplist, property);
	mosquitto_property_free_all(&property);

	check_count(proplist, 6);

	mosquitto_property_free_all(&proplist);
}

static void TEST_remove_all(void)
{
	mosquitto_property *proplist = NULL, *property;
	int rc;

	for(int i=0; i<100; i++){
		rc = mosquitto_property_add_byte(&proplist, MQTT_PROP_SHARED_SUB_AVAILABLE, 0);
		CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
		CU_ASSERT_PTR_NOT_NULL(proplist);
	}

	for(int i=0; i<100; i++){
		property = proplist;
		rc = mosquitto_property_remove(&proplist, property);
		CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
		mosquitto_property_free_all(&property);
		check_count(proplist, 100-i-1);
	}
	CU_ASSERT_PTR_NULL(proplist);
	mosquitto_property_free_all(&proplist);
}

static void TEST_remove_non_existent(void)
{
	mosquitto_property *proplist = NULL, *property = NULL;
	int rc;
	unsigned int len;

	len = property__get_remaining_length(proplist);
	CU_ASSERT_EQUAL(len, 1);

	rc = mosquitto_property_add_byte(&proplist, MQTT_PROP_SHARED_SUB_AVAILABLE, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	if(proplist){
		rc = mosquitto_property_add_byte(&property, MQTT_PROP_SHARED_SUB_AVAILABLE, 0);
		CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
		CU_ASSERT_PTR_NOT_NULL(property);
		if(property){
			rc = mosquitto_property_remove(&proplist, property);
			CU_ASSERT_EQUAL(rc, MOSQ_ERR_NOT_FOUND);
		}
	}
	mosquitto_property_free_all(&proplist);
	mosquitto_property_free_all(&property);
}

static void TEST_remove_invalid(void)
{
	mosquitto_property *proplist = NULL;
	int rc;
	unsigned int len;

	rc = mosquitto_property_remove(NULL, NULL);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);

	len = property__get_remaining_length(proplist);
	CU_ASSERT_EQUAL(len, 1);

	rc = mosquitto_property_add_byte(&proplist, MQTT_PROP_SHARED_SUB_AVAILABLE, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist);
	if(proplist){
		rc = mosquitto_property_remove(&proplist, NULL);
		CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
		rc = mosquitto_property_remove(NULL, proplist);
		CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	}
	mosquitto_property_free_all(&proplist);
}

/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */

int init_property_add_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("Property add", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit Property add test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Add nothing, check length", TEST_check_length)
			|| !CU_add_test(test_suite, "Add bad byte", TEST_add_bad_byte)
			|| !CU_add_test(test_suite, "Add bad int16", TEST_add_bad_int16)
			|| !CU_add_test(test_suite, "Add bad int32", TEST_add_bad_int32)
			|| !CU_add_test(test_suite, "Add bad varint", TEST_add_bad_varint)
			|| !CU_add_test(test_suite, "Add bad binary", TEST_add_bad_binary)
			|| !CU_add_test(test_suite, "Add bad string", TEST_add_bad_string)
			|| !CU_add_test(test_suite, "Add bad string pair", TEST_add_bad_string_pair)
			|| !CU_add_test(test_suite, "Add single byte", TEST_add_single_byte)
			|| !CU_add_test(test_suite, "Add single int16", TEST_add_single_int16)
			|| !CU_add_test(test_suite, "Add single int32", TEST_add_single_int32)
			|| !CU_add_test(test_suite, "Add single varint", TEST_add_single_varint)
			|| !CU_add_test(test_suite, "Add single binary", TEST_add_single_binary)
			|| !CU_add_test(test_suite, "Add single string", TEST_add_single_string)
			|| !CU_add_test(test_suite, "Add single string pair", TEST_add_single_string_pair)
			|| !CU_add_test(test_suite, "Add all CONNECT", TEST_add_all_connect)
			|| !CU_add_test(test_suite, "Add all CONNACK", TEST_add_all_connack)
			|| !CU_add_test(test_suite, "Remove single", TEST_remove_single)
			|| !CU_add_test(test_suite, "Remove all", TEST_remove_all)
			|| !CU_add_test(test_suite, "Remove non-existent", TEST_remove_non_existent)
			|| !CU_add_test(test_suite, "Remove invalid", TEST_remove_invalid)
			){

		printf("Error adding Property Add CUnit tests.\n");
		return 1;
	}

	return 0;
}
