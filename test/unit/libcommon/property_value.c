#include <stdio.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "mosquitto/mqtt_protocol.h"
#include "property_common.h"


static void TEST_value_byte_success(void)
{
	mosquitto_property *property = NULL;
	uint8_t value, value_set = 1;
	int rc;

	rc = mosquitto_property_add_byte(&property, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, value_set);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(property);
	if(property){
		value = mosquitto_property_byte_value(property);
		CU_ASSERT_EQUAL(value, value_set);

		mosquitto_property_free_all(&property);
	}
}


static void TEST_value_byte_fail(void)
{
	mosquitto_property *property = NULL;
	uint8_t value, value_set = 1;
	int rc;

	rc = mosquitto_property_add_int16(&property, MQTT_PROP_RECEIVE_MAXIMUM, value_set);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(property);
	if(property){
		value = mosquitto_property_byte_value(property);
		CU_ASSERT_EQUAL(value, 0);

		mosquitto_property_free_all(&property);
	}
}


static void TEST_value_int16_success(void)
{
	mosquitto_property *property = NULL;
	uint16_t value, value_set = 65535;
	int rc;

	rc = mosquitto_property_add_int16(&property, MQTT_PROP_RECEIVE_MAXIMUM, value_set);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(property);
	if(property){
		value = mosquitto_property_int16_value(property);
		CU_ASSERT_EQUAL(value, value_set);

		mosquitto_property_free_all(&property);
	}
}


static void TEST_value_int16_fail(void)
{
	mosquitto_property *property = NULL;
	uint16_t value, value_set = 65535;
	int rc;

	rc = mosquitto_property_add_int32(&property, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, value_set);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(property);
	if(property){
		value = mosquitto_property_int16_value(property);
		CU_ASSERT_EQUAL(value, 0);

		mosquitto_property_free_all(&property);
	}
}


static void TEST_value_int32_success(void)
{
	mosquitto_property *property = NULL;
	uint32_t value, value_set = 123456;
	int rc;

	rc = mosquitto_property_add_int32(&property, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, value_set);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(property);
	if(property){
		value = mosquitto_property_int32_value(property);
		CU_ASSERT_EQUAL(value, value_set);

		mosquitto_property_free_all(&property);
	}
}


static void TEST_value_int32_fail(void)
{
	mosquitto_property *property = NULL;
	uint32_t value, value_set = 123456;
	int rc;

	rc = mosquitto_property_add_varint(&property, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, value_set);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(property);
	if(property){
		value = mosquitto_property_int32_value(property);
		CU_ASSERT_EQUAL(value, 0);

		mosquitto_property_free_all(&property);
	}
}


static void TEST_value_varint_success(void)
{
	mosquitto_property *property = NULL;
	uint32_t value, value_set = 654321;
	int rc;

	rc = mosquitto_property_add_varint(&property, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, value_set);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(property);
	if(property){
		value = mosquitto_property_varint_value(property);
		CU_ASSERT_EQUAL(value, value_set);

		mosquitto_property_free_all(&property);
	}
}


static void TEST_value_varint_fail(void)
{
	mosquitto_property *property = NULL;
	uint32_t value;
	int rc;

	rc = mosquitto_property_add_int16(&property, MQTT_PROP_RECEIVE_MAXIMUM, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(property);
	if(property){
		value = mosquitto_property_varint_value(property);
		CU_ASSERT_EQUAL(value, 0);

		mosquitto_property_free_all(&property);
	}
}


static void TEST_value_binary_success(void)
{
	mosquitto_property *property = NULL;
	uint8_t value_set[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
	const uint8_t *value;
	uint16_t len;
	int rc;

	rc = mosquitto_property_add_binary(&property, MQTT_PROP_AUTHENTICATION_DATA, value_set, sizeof(value_set));
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(property);
	if(property){
		len = mosquitto_property_binary_value_length(property);
		value = mosquitto_property_binary_value(property);
		CU_ASSERT_EQUAL(len, sizeof(value_set));
		CU_ASSERT_NSTRING_EQUAL(value, value_set, sizeof(value_set));

		mosquitto_property_free_all(&property);
	}
}


static void TEST_value_binary_fail(void)
{
	mosquitto_property *property = NULL;
	const uint8_t *value;
	uint16_t len;
	int rc;

	rc = mosquitto_property_add_int16(&property, MQTT_PROP_RECEIVE_MAXIMUM, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(property);
	if(property){
		len = mosquitto_property_binary_value_length(property);
		value = mosquitto_property_binary_value(property);
		CU_ASSERT_EQUAL(len, 0);
		CU_ASSERT_PTR_NULL(value);

		mosquitto_property_free_all(&property);
	}
}


static void TEST_value_string_success(void)
{
	mosquitto_property *property = NULL;
	char value_set[] = "test";
	const char *value;
	uint16_t len;
	int rc;

	rc = mosquitto_property_add_string(&property, MQTT_PROP_AUTHENTICATION_METHOD, value_set);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(property);
	if(property){
		len = mosquitto_property_string_value_length(property);
		value = mosquitto_property_string_value(property);
		CU_ASSERT_EQUAL(len, strlen(value_set));
		CU_ASSERT_NSTRING_EQUAL(value, value_set, strlen(value_set));

		mosquitto_property_free_all(&property);
	}
}


static void TEST_value_string_fail(void)
{
	mosquitto_property *property = NULL;
	const char *value;
	uint16_t len;
	int rc;

	rc = mosquitto_property_add_int16(&property, MQTT_PROP_RECEIVE_MAXIMUM, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(property);
	if(property){
		len = mosquitto_property_string_value_length(property);
		value = mosquitto_property_string_value(property);
		CU_ASSERT_EQUAL(len, 0);
		CU_ASSERT_PTR_NULL(value);

		mosquitto_property_free_all(&property);
	}
}


static void TEST_value_string_pair_success(void)
{
	mosquitto_property *property = NULL;
	char value_set[] = "value";
	const char *value;
	uint16_t len;
	char name_set[] = "name";
	const char *name;
	int rc;

	rc = mosquitto_property_add_string_pair(&property, MQTT_PROP_USER_PROPERTY, name_set, value_set);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(property);
	if(property){
		len = mosquitto_property_string_value_length(property);
		value = mosquitto_property_string_value(property);
		CU_ASSERT_EQUAL(len, strlen(value_set));
		CU_ASSERT_NSTRING_EQUAL(value, value_set, strlen(value_set));

		len = mosquitto_property_string_name_length(property);
		name = mosquitto_property_string_name(property);
		CU_ASSERT_EQUAL(len, strlen(name_set));
		CU_ASSERT_NSTRING_EQUAL(name, name_set, strlen(name_set));

		mosquitto_property_free_all(&property);
	}
}


static void TEST_value_string_pair_fail(void)
{
	mosquitto_property *property = NULL;
	const char *value;
	uint16_t len;
	const char *name;
	int rc;

	rc = mosquitto_property_add_int16(&property, MQTT_PROP_RECEIVE_MAXIMUM, 1);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(property);
	if(property){
		len = mosquitto_property_string_value_length(property);
		value = mosquitto_property_string_value(property);
		CU_ASSERT_EQUAL(len, 0);
		CU_ASSERT_PTR_NULL(value);

		len = mosquitto_property_string_name_length(property);
		name = mosquitto_property_string_name(property);
		CU_ASSERT_EQUAL(len, 0);
		CU_ASSERT_PTR_NULL(name);

		mosquitto_property_free_all(&property);
	}
}


/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */


int init_property_value_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("Property value", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit Property value test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Byte value success", TEST_value_byte_success)
			|| !CU_add_test(test_suite, "Int16 value success", TEST_value_int16_success)
			|| !CU_add_test(test_suite, "Int32 value success", TEST_value_int32_success)
			|| !CU_add_test(test_suite, "Varint value success", TEST_value_varint_success)
			|| !CU_add_test(test_suite, "Binary value success", TEST_value_binary_success)
			|| !CU_add_test(test_suite, "String value success", TEST_value_string_success)
			|| !CU_add_test(test_suite, "String pair value success", TEST_value_string_pair_success)
			|| !CU_add_test(test_suite, "Byte value fail", TEST_value_byte_fail)
			|| !CU_add_test(test_suite, "Int16 value fail", TEST_value_int16_fail)
			|| !CU_add_test(test_suite, "Int32 value fail", TEST_value_int32_fail)
			|| !CU_add_test(test_suite, "Varint value fail", TEST_value_varint_fail)
			|| !CU_add_test(test_suite, "Binary value fail", TEST_value_binary_fail)
			|| !CU_add_test(test_suite, "String value fail", TEST_value_string_fail)
			|| !CU_add_test(test_suite, "String pair value fail", TEST_value_string_pair_fail)
			){

		printf("Error adding Property Value CUnit tests.\n");
		return 1;
	}

	return 0;
}
