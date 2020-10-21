#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "mqtt_protocol.h"
#include "property_mosq.h"
#include "packet_mosq.h"

static void generate_full_proplist(mosquitto_property **proplist)
{
	int rc;

	/* This isn't a valid proplist for sending, because it contains every
	 * property. Very useful for testing though. */
	rc = mosquitto_property_add_byte(proplist, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_int32(proplist, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, 3600);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_string(proplist, MQTT_PROP_CONTENT_TYPE, "application/json");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_string(proplist, MQTT_PROP_RESPONSE_TOPIC, "response/topic");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_binary(proplist, MQTT_PROP_CORRELATION_DATA, "correlation-data", strlen("correlation-data"));
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_varint(proplist, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 63);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_int32(proplist, MQTT_PROP_SESSION_EXPIRY_INTERVAL, 86400);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_string(proplist, MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER, "mosquitto-test");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_int16(proplist, MQTT_PROP_SERVER_KEEP_ALIVE, 180);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_string(proplist, MQTT_PROP_AUTHENTICATION_METHOD, "basic");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_binary(proplist, MQTT_PROP_AUTHENTICATION_DATA, "password", strlen("password"));
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_byte(proplist, MQTT_PROP_REQUEST_PROBLEM_INFORMATION, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_int32(proplist, MQTT_PROP_WILL_DELAY_INTERVAL, 1800);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_byte(proplist, MQTT_PROP_REQUEST_RESPONSE_INFORMATION, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_string(proplist, MQTT_PROP_RESPONSE_INFORMATION, "response");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_string(proplist, MQTT_PROP_SERVER_REFERENCE, "localhost");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_string(proplist, MQTT_PROP_REASON_STRING, "reason");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_int16(proplist, MQTT_PROP_RECEIVE_MAXIMUM, 1024);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_int16(proplist, MQTT_PROP_TOPIC_ALIAS_MAXIMUM, 64);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_int16(proplist, MQTT_PROP_TOPIC_ALIAS, 15);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_byte(proplist, MQTT_PROP_MAXIMUM_QOS, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_byte(proplist, MQTT_PROP_RETAIN_AVAILABLE, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_string_pair(proplist, MQTT_PROP_USER_PROPERTY, "user-agent", "mosquitto/test");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_int32(proplist, MQTT_PROP_MAXIMUM_PACKET_SIZE, 200000000);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_byte(proplist, MQTT_PROP_WILDCARD_SUB_AVAILABLE, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_byte(proplist, MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;
	rc = mosquitto_property_add_byte(proplist, MQTT_PROP_SHARED_SUB_AVAILABLE, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
}

static void generate_partial_proplist(mosquitto_property **proplist)
{
	int rc;

	// BYTE MISSING: MQTT_PROP_PAYLOAD_FORMAT_INDICATOR
	rc = mosquitto_property_add_int32(proplist, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, 3600);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	// STRING MISSING: MQTT_PROP_CONTENT_TYPE
	rc = mosquitto_property_add_string(proplist, MQTT_PROP_RESPONSE_TOPIC, "response/topic");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	// BINARY MISSING: MQTT_PROP_CORRELATION_DATA
	// VARINT MISSING: MQTT_PROP_SUBSCRIPTION_IDENTIFIER
	// INT32 MISSING: MQTT_PROP_SESSION_EXPIRY_INTERVAL
	rc = mosquitto_property_add_string(proplist, MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER, "mosquitto-test");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	// INT16 MISSING: MQTT_PROP_SERVER_KEEP_ALIVE
	rc = mosquitto_property_add_string(proplist, MQTT_PROP_AUTHENTICATION_METHOD, "basic");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	rc = mosquitto_property_add_binary(proplist, MQTT_PROP_AUTHENTICATION_DATA, "password", strlen("password"));
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	rc = mosquitto_property_add_byte(proplist, MQTT_PROP_REQUEST_PROBLEM_INFORMATION, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	rc = mosquitto_property_add_int32(proplist, MQTT_PROP_WILL_DELAY_INTERVAL, 1800);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	rc = mosquitto_property_add_byte(proplist, MQTT_PROP_REQUEST_RESPONSE_INFORMATION, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	rc = mosquitto_property_add_string(proplist, MQTT_PROP_RESPONSE_INFORMATION, "response");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	rc = mosquitto_property_add_string(proplist, MQTT_PROP_SERVER_REFERENCE, "localhost");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	rc = mosquitto_property_add_string(proplist, MQTT_PROP_REASON_STRING, "reason");
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	rc = mosquitto_property_add_int16(proplist, MQTT_PROP_RECEIVE_MAXIMUM, 1024);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	rc = mosquitto_property_add_int16(proplist, MQTT_PROP_TOPIC_ALIAS_MAXIMUM, 64);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	rc = mosquitto_property_add_int16(proplist, MQTT_PROP_TOPIC_ALIAS, 15);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	rc = mosquitto_property_add_byte(proplist, MQTT_PROP_MAXIMUM_QOS, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	rc = mosquitto_property_add_byte(proplist, MQTT_PROP_RETAIN_AVAILABLE, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	// STRING PAIR MISSING: MQTT_PROP_USER_PROPERTY
	rc = mosquitto_property_add_int32(proplist, MQTT_PROP_MAXIMUM_PACKET_SIZE, 200000000);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	rc = mosquitto_property_add_byte(proplist, MQTT_PROP_WILDCARD_SUB_AVAILABLE, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	rc = mosquitto_property_add_byte(proplist, MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	rc = mosquitto_property_add_byte(proplist, MQTT_PROP_SHARED_SUB_AVAILABLE, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
}

/* ========================================================================
 * SINGLE READ
 * ======================================================================== */

static void read_byte_helper(const mosquitto_property *proplist, int identifier, uint8_t expected_value)
{
	const mosquitto_property *prop;
	uint8_t value;

	prop = mosquitto_property_read_byte(proplist, identifier, &value, false);
	CU_ASSERT_PTR_NOT_NULL(prop);
	CU_ASSERT_EQUAL(value, expected_value);
}

static void read_int16_helper(const mosquitto_property *proplist, int identifier, uint16_t expected_value)
{
	const mosquitto_property *prop;
	uint16_t value;

	prop = mosquitto_property_read_int16(proplist, identifier, &value, false);
	CU_ASSERT_PTR_NOT_NULL(prop);
	CU_ASSERT_EQUAL(value, expected_value);
}

static void read_int32_helper(const mosquitto_property *proplist, int identifier, uint32_t expected_value)
{
	const mosquitto_property *prop;
	uint32_t value;

	prop = mosquitto_property_read_int32(proplist, identifier, &value, false);
	CU_ASSERT_PTR_NOT_NULL(prop);
	CU_ASSERT_EQUAL(value, expected_value);
}

static void read_varint_helper(const mosquitto_property *proplist, int identifier, uint32_t expected_value)
{
	const mosquitto_property *prop;
	uint32_t value;

	prop = mosquitto_property_read_varint(proplist, identifier, &value, false);
	CU_ASSERT_PTR_NOT_NULL(prop);
	CU_ASSERT_EQUAL(value, expected_value);
}

static void read_binary_helper(const mosquitto_property *proplist, int identifier, void *expected_value, uint16_t expected_length)
{
	const mosquitto_property *prop;
	void *value = NULL;
	uint16_t length;

	prop = mosquitto_property_read_binary(proplist, identifier, &value, &length, false);
	CU_ASSERT_PTR_NOT_NULL(prop);
	CU_ASSERT_EQUAL(length, expected_length);
	CU_ASSERT_PTR_NOT_NULL(value);
	if(value){
		CU_ASSERT_NSTRING_EQUAL(value, expected_value, expected_length);
	}
	free(value);
}

static void read_string_helper(const mosquitto_property *proplist, int identifier, char *expected_value)
{
	const mosquitto_property *prop;
	char *value = NULL;

	prop = mosquitto_property_read_string(proplist, identifier, &value, false);
	CU_ASSERT_PTR_NOT_NULL(prop);
	CU_ASSERT_PTR_NOT_NULL(value);
	if(value){
		CU_ASSERT_STRING_EQUAL(value, expected_value);
	}
	free(value);
}

static void read_string_pair_helper(const mosquitto_property *proplist, int identifier, char *expected_key, char *expected_value)
{
	const mosquitto_property *prop;
	char *key = NULL, *value = NULL;

	prop = mosquitto_property_read_string_pair(proplist, identifier, &key, &value, false);
	CU_ASSERT_PTR_NOT_NULL(prop);

	CU_ASSERT_PTR_NOT_NULL(key);
	if(key){
		CU_ASSERT_STRING_EQUAL(key, expected_key);
	}

	CU_ASSERT_PTR_NOT_NULL(value);
	if(value){
		CU_ASSERT_STRING_EQUAL(value, expected_value);
	}
	free(key);
	free(value);
}


static void TEST_read_single_byte(void)
{
	int rc;
	mosquitto_property *proplist = NULL, *proplist_copy = NULL;

	generate_full_proplist(&proplist);
	if(!proplist) return;

	read_byte_helper(proplist, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 1);
	read_byte_helper(proplist, MQTT_PROP_REQUEST_PROBLEM_INFORMATION, 1);
	read_byte_helper(proplist, MQTT_PROP_REQUEST_RESPONSE_INFORMATION, 1);
	read_byte_helper(proplist, MQTT_PROP_MAXIMUM_QOS, 0);
	read_byte_helper(proplist, MQTT_PROP_RETAIN_AVAILABLE, 0);
	read_byte_helper(proplist, MQTT_PROP_WILDCARD_SUB_AVAILABLE, 0);
	read_byte_helper(proplist, MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE, 0);
	read_byte_helper(proplist, MQTT_PROP_SHARED_SUB_AVAILABLE, 0);

	rc = mosquitto_property_copy_all(&proplist_copy, proplist);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist_copy);

	read_byte_helper(proplist_copy, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 1);
	read_byte_helper(proplist_copy, MQTT_PROP_REQUEST_PROBLEM_INFORMATION, 1);
	read_byte_helper(proplist_copy, MQTT_PROP_REQUEST_RESPONSE_INFORMATION, 1);
	read_byte_helper(proplist_copy, MQTT_PROP_MAXIMUM_QOS, 0);
	read_byte_helper(proplist_copy, MQTT_PROP_RETAIN_AVAILABLE, 0);
	read_byte_helper(proplist_copy, MQTT_PROP_WILDCARD_SUB_AVAILABLE, 0);
	read_byte_helper(proplist_copy, MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE, 0);
	read_byte_helper(proplist_copy, MQTT_PROP_SHARED_SUB_AVAILABLE, 0);

	mosquitto_property_free_all(&proplist);
	mosquitto_property_free_all(&proplist_copy);
}

static void TEST_read_single_int16(void)
{
	int rc;
	mosquitto_property *proplist = NULL, *proplist_copy = NULL;

	generate_full_proplist(&proplist);
	if(!proplist) return;

	read_int16_helper(proplist, MQTT_PROP_SERVER_KEEP_ALIVE, 180);
	read_int16_helper(proplist, MQTT_PROP_RECEIVE_MAXIMUM, 1024);
	read_int16_helper(proplist, MQTT_PROP_TOPIC_ALIAS_MAXIMUM, 64);
	read_int16_helper(proplist, MQTT_PROP_TOPIC_ALIAS, 15);

	rc = mosquitto_property_copy_all(&proplist_copy, proplist);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist_copy);

	read_int16_helper(proplist_copy, MQTT_PROP_SERVER_KEEP_ALIVE, 180);
	read_int16_helper(proplist_copy, MQTT_PROP_RECEIVE_MAXIMUM, 1024);
	read_int16_helper(proplist_copy, MQTT_PROP_TOPIC_ALIAS_MAXIMUM, 64);
	read_int16_helper(proplist_copy, MQTT_PROP_TOPIC_ALIAS, 15);

	mosquitto_property_free_all(&proplist);
	mosquitto_property_free_all(&proplist_copy);
}

static void TEST_read_single_int32(void)
{
	int rc;
	mosquitto_property *proplist = NULL, *proplist_copy = NULL;

	generate_full_proplist(&proplist);
	if(!proplist) return;

	read_int32_helper(proplist, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, 3600);
	read_int32_helper(proplist, MQTT_PROP_SESSION_EXPIRY_INTERVAL, 86400);
	read_int32_helper(proplist, MQTT_PROP_WILL_DELAY_INTERVAL, 1800);
	read_int32_helper(proplist, MQTT_PROP_MAXIMUM_PACKET_SIZE, 200000000);

	rc = mosquitto_property_copy_all(&proplist_copy, proplist);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist_copy);

	read_int32_helper(proplist_copy, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, 3600);
	read_int32_helper(proplist_copy, MQTT_PROP_SESSION_EXPIRY_INTERVAL, 86400);
	read_int32_helper(proplist_copy, MQTT_PROP_WILL_DELAY_INTERVAL, 1800);
	read_int32_helper(proplist_copy, MQTT_PROP_MAXIMUM_PACKET_SIZE, 200000000);

	mosquitto_property_free_all(&proplist);
	mosquitto_property_free_all(&proplist_copy);
}

static void TEST_read_single_varint(void)
{
	int rc;
	mosquitto_property *proplist = NULL, *proplist_copy = NULL;

	generate_full_proplist(&proplist);
	if(!proplist) return;

	read_varint_helper(proplist, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 63);

	rc = mosquitto_property_copy_all(&proplist_copy, proplist);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist_copy);

	read_varint_helper(proplist_copy, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 63);

	mosquitto_property_free_all(&proplist);
	mosquitto_property_free_all(&proplist_copy);
}

static void TEST_read_single_binary(void)
{
	int rc;
	mosquitto_property *proplist = NULL, *proplist_copy = NULL;

	generate_full_proplist(&proplist);
	if(!proplist) return;

	read_binary_helper(proplist, MQTT_PROP_CORRELATION_DATA, "correlation-data", strlen("correlation-data"));
	read_binary_helper(proplist, MQTT_PROP_AUTHENTICATION_DATA, "password", strlen("password"));

	rc = mosquitto_property_copy_all(&proplist_copy, proplist);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist_copy);

	if(proplist_copy){
		read_binary_helper(proplist_copy, MQTT_PROP_CORRELATION_DATA, "correlation-data", strlen("correlation-data"));
		read_binary_helper(proplist_copy, MQTT_PROP_AUTHENTICATION_DATA, "password", strlen("password"));
	}

	mosquitto_property_free_all(&proplist);
	mosquitto_property_free_all(&proplist_copy);
}

static void TEST_read_single_string(void)
{
	int rc;
	mosquitto_property *proplist = NULL, *proplist_copy = NULL;

	generate_full_proplist(&proplist);
	if(!proplist) return;

	read_string_helper(proplist, MQTT_PROP_CONTENT_TYPE, "application/json");
	read_string_helper(proplist, MQTT_PROP_RESPONSE_TOPIC, "response/topic");
	read_string_helper(proplist, MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER, "mosquitto-test");
	read_string_helper(proplist, MQTT_PROP_AUTHENTICATION_METHOD, "basic");
	read_string_helper(proplist, MQTT_PROP_RESPONSE_INFORMATION, "response");
	read_string_helper(proplist, MQTT_PROP_SERVER_REFERENCE, "localhost");
	read_string_helper(proplist, MQTT_PROP_REASON_STRING, "reason");

	rc = mosquitto_property_copy_all(&proplist_copy, proplist);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist_copy);

	if(proplist_copy){
		read_string_helper(proplist_copy, MQTT_PROP_CONTENT_TYPE, "application/json");
		read_string_helper(proplist_copy, MQTT_PROP_RESPONSE_TOPIC, "response/topic");
		read_string_helper(proplist_copy, MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER, "mosquitto-test");
		read_string_helper(proplist_copy, MQTT_PROP_AUTHENTICATION_METHOD, "basic");
		read_string_helper(proplist_copy, MQTT_PROP_RESPONSE_INFORMATION, "response");
		read_string_helper(proplist_copy, MQTT_PROP_SERVER_REFERENCE, "localhost");
		read_string_helper(proplist_copy, MQTT_PROP_REASON_STRING, "reason");
	}

	mosquitto_property_free_all(&proplist);
	mosquitto_property_free_all(&proplist_copy);
}

static void TEST_read_single_string_pair(void)
{
	int rc;
	mosquitto_property *proplist = NULL, *proplist_copy = NULL;

	generate_full_proplist(&proplist);
	if(!proplist) return;

	read_string_pair_helper(proplist, MQTT_PROP_USER_PROPERTY, "user-agent", "mosquitto/test");

	rc = mosquitto_property_copy_all(&proplist_copy, proplist);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist_copy);

	if(proplist_copy){
		read_string_pair_helper(proplist_copy, MQTT_PROP_USER_PROPERTY, "user-agent", "mosquitto/test");
	}

	mosquitto_property_free_all(&proplist);
	mosquitto_property_free_all(&proplist_copy);
}

/* ========================================================================
 * MISSING READ
 * ======================================================================== */

static void missing_read_helper(mosquitto_property *proplist)
{
	const mosquitto_property *prop;
	uint8_t byte_value;
	uint16_t int16_value;
	uint32_t int32_value;
	char *key, *value;
	uint16_t length;

	/* MISSING */
	prop = mosquitto_property_read_byte(proplist, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, &byte_value, false);
	CU_ASSERT_PTR_NULL(prop);

	/* NOT MISSING */
	prop = mosquitto_property_read_int32(proplist, MQTT_PROP_WILL_DELAY_INTERVAL, &int32_value, false);
	CU_ASSERT_PTR_NOT_NULL(prop);
	CU_ASSERT_EQUAL(int32_value, 1800);

	/* MISSING */
	value = NULL;
	prop = mosquitto_property_read_string(proplist, MQTT_PROP_CONTENT_TYPE, &value, false);
	CU_ASSERT_PTR_NULL(prop);

	/* NOT MISSING */
	value = NULL;
	prop = mosquitto_property_read_string(proplist, MQTT_PROP_RESPONSE_TOPIC, &value, false);
	CU_ASSERT_PTR_NOT_NULL(prop);
	CU_ASSERT_PTR_NOT_NULL(value);
	if(value){
		CU_ASSERT_STRING_EQUAL(value, "response/topic");
		free(value);
	}

	/* MISSING */
	prop = mosquitto_property_read_binary(proplist, MQTT_PROP_CORRELATION_DATA, (void **)&value, &length, false);
	CU_ASSERT_PTR_NULL(prop);

	/* NOT MISSING */
	prop = mosquitto_property_read_byte(proplist, MQTT_PROP_REQUEST_PROBLEM_INFORMATION, &byte_value, false);
	CU_ASSERT_PTR_NOT_NULL(prop);
	CU_ASSERT_EQUAL(byte_value, 1);

	/* MISSING */
	prop = mosquitto_property_read_varint(proplist, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, &int32_value, false);
	CU_ASSERT_PTR_NULL(prop);

	/* NOT MISSING */
	value = NULL;
	prop = mosquitto_property_read_string(proplist, MQTT_PROP_SERVER_REFERENCE, &value, false);
	CU_ASSERT_PTR_NOT_NULL(prop);
	CU_ASSERT_PTR_NOT_NULL(value);
	if(value){
		CU_ASSERT_STRING_EQUAL(value, "localhost");
		free(value);
	}

	/* MISSING */
	prop = mosquitto_property_read_int32(proplist, MQTT_PROP_SESSION_EXPIRY_INTERVAL, &int32_value, false);
	CU_ASSERT_PTR_NULL(prop);

	/* NOT MISSING */
	value = NULL;
	prop = mosquitto_property_read_binary(proplist, MQTT_PROP_AUTHENTICATION_DATA, (void **)&value, &length, false);
	CU_ASSERT_PTR_NOT_NULL(prop);
	CU_ASSERT_PTR_NOT_NULL(value);
	if(value){
		CU_ASSERT_NSTRING_EQUAL(value, "password", strlen("password"));
		CU_ASSERT_EQUAL(length, strlen("password"));
		free(value);
	}

	/* MISSING */
	prop = mosquitto_property_read_int16(proplist, MQTT_PROP_SERVER_KEEP_ALIVE, &int16_value, false);
	CU_ASSERT_PTR_NULL(prop);

	/* NOT MISSING */
	prop = mosquitto_property_read_int16(proplist, MQTT_PROP_RECEIVE_MAXIMUM, &int16_value, false);
	CU_ASSERT_PTR_NOT_NULL(prop);
	CU_ASSERT_EQUAL(int16_value, 1024);

	/* MISSING */
	prop = mosquitto_property_read_string_pair(proplist, MQTT_PROP_USER_PROPERTY, &key, &value, false);
	CU_ASSERT_PTR_NULL(prop);
}


static void TEST_read_missing(void)
{
	mosquitto_property *proplist = NULL, *proplist_copy = NULL;
	int rc;

	generate_partial_proplist(&proplist);
	if(!proplist) return;

	missing_read_helper(proplist);
	rc = mosquitto_property_copy_all(&proplist_copy, proplist);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(proplist_copy);
	if(proplist_copy){
		missing_read_helper(proplist_copy);
	}

	mosquitto_property_free_all(&proplist);
	mosquitto_property_free_all(&proplist_copy);
}

/* ========================================================================
 * STRING TO PROPERTY INFO
 * ======================================================================== */

static void string_to_property_info_helper(const char *str, int rc_expected, int identifier_expected, int type_expected)
{
	int rc;
	int identifier, type;

	rc = mosquitto_string_to_property_info(str, &identifier, &type);
	CU_ASSERT_EQUAL(rc, rc_expected);
	if(rc == MOSQ_ERR_SUCCESS){
		CU_ASSERT_EQUAL(identifier, identifier_expected);
		CU_ASSERT_EQUAL(type, type_expected);
	}
}

static void TEST_string_to_property_info(void)
{
	string_to_property_info_helper("payload-format-indicator", MOSQ_ERR_SUCCESS, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, MQTT_PROP_TYPE_BYTE);
	string_to_property_info_helper("message-expiry-interval", MOSQ_ERR_SUCCESS, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, MQTT_PROP_TYPE_INT32);
	string_to_property_info_helper("content-type", MOSQ_ERR_SUCCESS, MQTT_PROP_CONTENT_TYPE, MQTT_PROP_TYPE_STRING);
	string_to_property_info_helper("response-topic", MOSQ_ERR_SUCCESS, MQTT_PROP_RESPONSE_TOPIC, MQTT_PROP_TYPE_STRING);
	string_to_property_info_helper("correlation-data", MOSQ_ERR_SUCCESS, MQTT_PROP_CORRELATION_DATA, MQTT_PROP_TYPE_BINARY);
	string_to_property_info_helper("subscription-identifier", MOSQ_ERR_SUCCESS, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, MQTT_PROP_TYPE_VARINT);
	string_to_property_info_helper("session-expiry-interval", MOSQ_ERR_SUCCESS, MQTT_PROP_SESSION_EXPIRY_INTERVAL, MQTT_PROP_TYPE_INT32);
	string_to_property_info_helper("assigned-client-identifier", MOSQ_ERR_SUCCESS, MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER, MQTT_PROP_TYPE_STRING);
	string_to_property_info_helper("server-keep-alive", MOSQ_ERR_SUCCESS, MQTT_PROP_SERVER_KEEP_ALIVE, MQTT_PROP_TYPE_INT16);
	string_to_property_info_helper("authentication-method", MOSQ_ERR_SUCCESS, MQTT_PROP_AUTHENTICATION_METHOD, MQTT_PROP_TYPE_STRING);
	string_to_property_info_helper("authentication-data", MOSQ_ERR_SUCCESS, MQTT_PROP_AUTHENTICATION_DATA, MQTT_PROP_TYPE_BINARY);
	string_to_property_info_helper("request-problem-information", MOSQ_ERR_SUCCESS, MQTT_PROP_REQUEST_PROBLEM_INFORMATION, MQTT_PROP_TYPE_BYTE);
	string_to_property_info_helper("will-delay-interval", MOSQ_ERR_SUCCESS, MQTT_PROP_WILL_DELAY_INTERVAL, MQTT_PROP_TYPE_INT32);
	string_to_property_info_helper("request-response-information", MOSQ_ERR_SUCCESS, MQTT_PROP_REQUEST_RESPONSE_INFORMATION, MQTT_PROP_TYPE_BYTE);
	string_to_property_info_helper("response-information", MOSQ_ERR_SUCCESS, MQTT_PROP_RESPONSE_INFORMATION, MQTT_PROP_TYPE_STRING);
	string_to_property_info_helper("server-reference", MOSQ_ERR_SUCCESS, MQTT_PROP_SERVER_REFERENCE, MQTT_PROP_TYPE_STRING);
	string_to_property_info_helper("reason-string", MOSQ_ERR_SUCCESS, MQTT_PROP_REASON_STRING, MQTT_PROP_TYPE_STRING);
	string_to_property_info_helper("receive-maximum", MOSQ_ERR_SUCCESS, MQTT_PROP_RECEIVE_MAXIMUM, MQTT_PROP_TYPE_INT16);
	string_to_property_info_helper("topic-alias-maximum", MOSQ_ERR_SUCCESS, MQTT_PROP_TOPIC_ALIAS_MAXIMUM, MQTT_PROP_TYPE_INT16);
	string_to_property_info_helper("topic-alias", MOSQ_ERR_SUCCESS, MQTT_PROP_TOPIC_ALIAS, MQTT_PROP_TYPE_INT16);
	string_to_property_info_helper("maximum-qos", MOSQ_ERR_SUCCESS, MQTT_PROP_MAXIMUM_QOS, MQTT_PROP_TYPE_BYTE);
	string_to_property_info_helper("retain-available", MOSQ_ERR_SUCCESS, MQTT_PROP_RETAIN_AVAILABLE, MQTT_PROP_TYPE_BYTE);
	string_to_property_info_helper("user-property", MOSQ_ERR_SUCCESS, MQTT_PROP_USER_PROPERTY, MQTT_PROP_TYPE_STRING_PAIR);
	string_to_property_info_helper("maximum-packet-size", MOSQ_ERR_SUCCESS, MQTT_PROP_MAXIMUM_PACKET_SIZE, MQTT_PROP_TYPE_INT32);
	string_to_property_info_helper("wildcard-subscription-available", MOSQ_ERR_SUCCESS, MQTT_PROP_WILDCARD_SUB_AVAILABLE, MQTT_PROP_TYPE_BYTE);
	string_to_property_info_helper("subscription-identifier-available", MOSQ_ERR_SUCCESS, MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE, MQTT_PROP_TYPE_BYTE);
	string_to_property_info_helper("shared-subscription-available", MOSQ_ERR_SUCCESS, MQTT_PROP_SHARED_SUB_AVAILABLE, MQTT_PROP_TYPE_BYTE);

	string_to_property_info_helper("payload-format-indicator1", MOSQ_ERR_INVAL, 0, 0);
	string_to_property_info_helper("payload", MOSQ_ERR_INVAL, 0, 0);
	string_to_property_info_helper("", MOSQ_ERR_INVAL, 0, 0);
	string_to_property_info_helper(NULL, MOSQ_ERR_INVAL, 0, 0);
}


/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */

int init_property_user_read_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("Property user read", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit Property user read test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Read single byte", TEST_read_single_byte)
			|| !CU_add_test(test_suite, "Read single int16", TEST_read_single_int16)
			|| !CU_add_test(test_suite, "Read single int32", TEST_read_single_int32)
			|| !CU_add_test(test_suite, "Read single varint", TEST_read_single_varint)
			|| !CU_add_test(test_suite, "Read single binary", TEST_read_single_binary)
			|| !CU_add_test(test_suite, "Read single string", TEST_read_single_string)
			|| !CU_add_test(test_suite, "Read single string pair", TEST_read_single_string_pair)
			|| !CU_add_test(test_suite, "Read missing", TEST_read_missing)
			|| !CU_add_test(test_suite, "String to property info", TEST_string_to_property_info)
			){

		printf("Error adding Property Add CUnit tests.\n");
		return 1;
	}

	return 0;
}
