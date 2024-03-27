/* Tests for int to string functions. */

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "mosquitto.h"

struct prop_id{
	const char *name;
	int proptype;
};

static void TEST_string_to_property_info(void)
{
	const struct prop_id checks[50] = {
		{ NULL, 0 },
		{ "payload-format-indicator", MQTT_PROP_TYPE_BYTE },
		{ "message-expiry-interval", MQTT_PROP_TYPE_INT32 },
		{ "content-type", MQTT_PROP_TYPE_STRING },
		{ NULL, 0 },
		{ NULL, 0 },
		{ NULL, 0 },
		{ NULL, 0 },
		{ "response-topic", MQTT_PROP_TYPE_STRING },
		{ "correlation-data", MQTT_PROP_TYPE_BINARY },
		{ NULL, 0 },
		{ "subscription-identifier", MQTT_PROP_TYPE_VARINT },
		{ NULL, 0 },
		{ NULL, 0 },
		{ NULL, 0 },
		{ NULL, 0 },
		{ NULL, 0 },
		{ "session-expiry-interval", MQTT_PROP_TYPE_INT32 },
		{ "assigned-client-identifier", MQTT_PROP_TYPE_STRING },
		{ "server-keep-alive", MQTT_PROP_TYPE_INT16 },
		{ NULL, 0 },
		{ "authentication-method", MQTT_PROP_TYPE_STRING },
		{ "authentication-data", MQTT_PROP_TYPE_BINARY },
		{ "request-problem-information", MQTT_PROP_TYPE_BYTE },
		{ "will-delay-interval", MQTT_PROP_TYPE_INT32 },
		{ "request-response-information", MQTT_PROP_TYPE_BYTE },
		{ "response-information", MQTT_PROP_TYPE_STRING },
		{ NULL, 0 },
		{ "server-reference", MQTT_PROP_TYPE_STRING },
		{ NULL, 0 },
		{ NULL, 0 },
		{ "reason-string", MQTT_PROP_TYPE_STRING },
		{ NULL, 0 },
		{ "receive-maximum", MQTT_PROP_TYPE_INT16 },
		{ "topic-alias-maximum", MQTT_PROP_TYPE_INT16 },
		{ "topic-alias", MQTT_PROP_TYPE_INT16 },
		{ "maximum-qos", MQTT_PROP_TYPE_BYTE },
		{ "retain-available", MQTT_PROP_TYPE_BYTE },
		{ "user-property", MQTT_PROP_TYPE_STRING_PAIR },
		{ "maximum-packet-size", MQTT_PROP_TYPE_INT32 },
		{ "wildcard-subscription-available", MQTT_PROP_TYPE_BYTE },
		{ "subscription-identifier-available", MQTT_PROP_TYPE_BYTE },
		{ "shared-subscription-available", MQTT_PROP_TYPE_BYTE },
		{ NULL, 0 },
		{ NULL, 0 },
		{ NULL, 0 },
		{ NULL, 0 },
		{ NULL, 0 },
		{ NULL, 0 },
		{ NULL, 0 },
	};

	for(int i=0; i<50; i++){
		int rc, identifier, proptype;
		rc = mosquitto_string_to_property_info(checks[i].name, &identifier, &proptype);
		if(checks[i].name == NULL){
			CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
		}else{
			CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
			CU_ASSERT_EQUAL(identifier, i);
			CU_ASSERT_EQUAL(proptype, checks[i].proptype);
		}
	}
}

static void TEST_mosquitto_strerror(void)
{
	const char *str;
	int used[] = {-6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
		12, /* 13, */ 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 31, 32,
		128, 131, 133, 134, 136, 137, 138, 140, 142, 147, 148, 152, 154, 159};

	/* Iterate over all possible errors, checking we have a place holder for all
	 * unused errors, and that all used errors do not have place holder text. */
	for(int err=-256; err<256; err++){
		str = mosquitto_strerror(err);
		CU_ASSERT_PTR_NOT_NULL(str);
		if(str){
			bool is_used = false;
			for(size_t i=0; i<sizeof(used)/sizeof(int); i++){
				if(err == used[i]){
					is_used = true;
					break;
				}
			}
			if(is_used){
				CU_ASSERT_STRING_NOT_EQUAL(str, "Unknown error");
				if(!strcmp(str, "Unknown error")){
					printf("%d: %s\n", err, str);
				}
			}else{
				CU_ASSERT_STRING_EQUAL(str, "Unknown error");
				if(strcmp(str, "Unknown error")){
					printf("%d: %s\n", err, str);
				}
			}
		}
	}
}

static void TEST_mosquitto_connack_string(void)
{
	const char *str;
	uint8_t used[] = {0, 1, 2, 3, 4, 5};

	/* Iterate over all possible codes, checking we have a place holder for all
	 * unused codes, and that all used codes do not have place holder text. */
	for(int code=0; code<256; code++){
		str = mosquitto_connack_string(code);
		CU_ASSERT_PTR_NOT_NULL(str);
		if(str){
			bool is_used = false;
			for(size_t i=0; i<sizeof(used); i++){
				if(code == used[i]){
					is_used = true;
					break;
				}
			}
			if(is_used){
				CU_ASSERT_STRING_NOT_EQUAL(str, "Connection Refused: unknown reason");
				if(!strcmp(str, "Connection Refused: unknown reason.")){
					printf("%d: %s\n", code, str);
				}
			}else{
				CU_ASSERT_STRING_EQUAL(str, "Connection Refused: unknown reason");
				if(strcmp(str, "Connection Refused: unknown reason")){
					printf("%d: %s\n", code, str);
				}
			}
		}
	}
}

static void TEST_mosquitto_reason_string(void)
{
	const char *str;
	uint8_t used[] = {0, 1, 2, 4, 16, 17, 24, 25, 128, 129, 130, 131, 132, 133,
		134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147,
		148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161,
		162};

	/* Iterate over all possible codes, checking we have a place holder for all
	 * unused codes, and that all used codes do not have place holder text. */
	for(int code=0; code<256; code++){
		str = mosquitto_reason_string(code);
		CU_ASSERT_PTR_NOT_NULL(str);
		if(str){
			bool is_used = false;
			for(size_t i=0; i<sizeof(used); i++){
				if(code == used[i]){
					is_used = true;
					break;
				}
			}
			if(is_used){
				CU_ASSERT_STRING_NOT_EQUAL(str, "Unknown reason");
				if(!strcmp(str, "Unknown reason")){
					printf("%d: %s\n", code, str);
				}
			}else{
				CU_ASSERT_STRING_EQUAL(str, "Unknown reason");
				if(strcmp(str, "Unknown reason")){
					printf("%d: %s\n", code, str);
				}
			}
		}
	}
}

static void TEST_mosquitto_string_to_command(void)
{
	int rc, cmd;

	rc = mosquitto_string_to_command("CONNECT", &cmd);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(cmd, CMD_CONNECT);

	rc = mosquitto_string_to_command("CONNACK", &cmd);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(cmd, CMD_CONNACK);

	rc = mosquitto_string_to_command("PUBLISH", &cmd);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(cmd, CMD_PUBLISH);

	rc = mosquitto_string_to_command("PUBACK", &cmd);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(cmd, CMD_PUBACK);

	rc = mosquitto_string_to_command("PUBREC", &cmd);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(cmd, CMD_PUBREC);

	rc = mosquitto_string_to_command("PUBREL", &cmd);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(cmd, CMD_PUBREL);

	rc = mosquitto_string_to_command("PUBCOMP", &cmd);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(cmd, CMD_PUBCOMP);

	rc = mosquitto_string_to_command("SUBSCRIBE", &cmd);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(cmd, CMD_SUBSCRIBE);

	rc = mosquitto_string_to_command("SUBACK", &cmd);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(cmd, CMD_SUBACK);

	rc = mosquitto_string_to_command("UNSUBSCRIBE", &cmd);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(cmd, CMD_UNSUBSCRIBE);

	rc = mosquitto_string_to_command("UNSUBACK", &cmd);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(cmd, CMD_UNSUBACK);

	rc = mosquitto_string_to_command("DISCONNECT", &cmd);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(cmd, CMD_DISCONNECT);

	rc = mosquitto_string_to_command("AUTH", &cmd);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(cmd, CMD_AUTH);

	rc = mosquitto_string_to_command("WILL", &cmd);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(cmd, CMD_WILL);

	rc = mosquitto_string_to_command("CONNACT", &cmd);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(cmd, 0);
}

/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */

int init_strings_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("Strings", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "mosquitto_strerror", TEST_mosquitto_strerror)
			|| !CU_add_test(test_suite, "mosquitto_connack_string", TEST_mosquitto_connack_string)
			|| !CU_add_test(test_suite, "mosquitto_reason_string", TEST_mosquitto_reason_string)
			|| !CU_add_test(test_suite, "mosquitto_string_to_command", TEST_mosquitto_string_to_command)
			|| !CU_add_test(test_suite, "mosquitto_string_to_property_info", TEST_string_to_property_info)
			){

		printf("Error adding Strings CUnit tests.\n");
		return 1;
	}

	return 0;
}


