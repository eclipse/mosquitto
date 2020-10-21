#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "mqtt_protocol.h"
#include "property_mosq.h"
#include "packet_mosq.h"

static void byte_prop_read_helper(
		int command,
		uint8_t *payload,
		uint32_t remaining_length,
		int rc_expected,
		uint8_t identifier,
		uint8_t value_expected)
{
	struct mosquitto__packet packet;
	mosquitto_property *properties;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = property__read_all(command, &packet, &properties);

	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(packet.pos, remaining_length);
	if(properties){
		CU_ASSERT_EQUAL(properties->identifier, identifier);
		CU_ASSERT_EQUAL(properties->value.i8, value_expected);
		CU_ASSERT_PTR_EQUAL(properties->next, NULL);
		CU_ASSERT_EQUAL(property__get_length_all(properties), 2);
		mosquitto_property_free_all(&properties);
	}
	CU_ASSERT_PTR_EQUAL(properties, NULL);
}

static void duplicate_byte_helper(int command, uint8_t identifier)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 4; /* Proplen = (Identifier + byte)*2 */
	payload[1] = identifier;
	payload[2] = 1;
	payload[3] = identifier;
	payload[4] = 0;

	byte_prop_read_helper(command, payload, 5, MOSQ_ERR_DUPLICATE_PROPERTY, identifier, 1);
}

static void bad_byte_helper(int command, uint8_t identifier)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = identifier;
	payload[2] = 2; /* 0, 1 are only valid values */

	byte_prop_read_helper(command, payload, 3, MOSQ_ERR_PROTOCOL, identifier, 0);
}


static void int32_prop_read_helper(
		int command,
		uint8_t *payload,
		uint32_t remaining_length,
		int rc_expected,
		uint8_t identifier,
		uint32_t value_expected)
{
	struct mosquitto__packet packet;
	mosquitto_property *properties;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = property__read_all(command, &packet, &properties);

	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(packet.pos, remaining_length);
	if(properties){
		CU_ASSERT_EQUAL(properties->identifier, identifier);
		CU_ASSERT_EQUAL(properties->value.i32, value_expected);
		CU_ASSERT_PTR_EQUAL(properties->next, NULL);
		CU_ASSERT_EQUAL(property__get_length_all(properties), 5);
		mosquitto_property_free_all(&properties);
	}
	CU_ASSERT_PTR_EQUAL(properties, NULL);
}

static void duplicate_int32_helper(int command, uint8_t identifier)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 10; /* Proplen = (Identifier + int32)*2 */
	payload[1] = identifier;
	payload[2] = 1;
	payload[3] = 1;
	payload[4] = 1;
	payload[5] = 1;
	payload[6] = identifier;
	payload[7] = 0;
	payload[8] = 0;
	payload[9] = 0;
	payload[10] = 0;

	int32_prop_read_helper(command, payload, 11, MOSQ_ERR_DUPLICATE_PROPERTY, identifier, 1);
}


static void int16_prop_read_helper(
		int command,
		uint8_t *payload,
		uint32_t remaining_length,
		int rc_expected,
		uint8_t identifier,
		uint16_t value_expected)
{
	struct mosquitto__packet packet;
	mosquitto_property *properties;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = property__read_all(command, &packet, &properties);

	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(packet.pos, remaining_length);
	if(properties){
		CU_ASSERT_EQUAL(properties->identifier, identifier);
		CU_ASSERT_EQUAL(properties->value.i16, value_expected);
		CU_ASSERT_PTR_EQUAL(properties->next, NULL);
		CU_ASSERT_EQUAL(property__get_length_all(properties), 3);
		mosquitto_property_free_all(&properties);
	}
	CU_ASSERT_PTR_EQUAL(properties, NULL);
}

static void duplicate_int16_helper(int command, uint8_t identifier)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 6; /* Proplen = (Identifier + int16)*2 */
	payload[1] = identifier;
	payload[2] = 1;
	payload[3] = 1;
	payload[4] = identifier;
	payload[5] = 0;
	payload[6] = 0;

	int16_prop_read_helper(command, payload, 7, MOSQ_ERR_DUPLICATE_PROPERTY, identifier, 1);
}

static void string_prop_read_helper(
		int command,
		uint8_t *payload,
		uint32_t remaining_length,
		int rc_expected,
		uint8_t identifier,
		const char *value_expected)
{
	struct mosquitto__packet packet;
	mosquitto_property *properties;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = property__read_all(command, &packet, &properties);

	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(packet.pos, remaining_length);
	if(properties){
		CU_ASSERT_EQUAL(properties->identifier, identifier);
		CU_ASSERT_EQUAL(properties->value.s.len, strlen(value_expected));
		CU_ASSERT_STRING_EQUAL(properties->value.s.v, value_expected);
		CU_ASSERT_PTR_EQUAL(properties->next, NULL);
		CU_ASSERT_EQUAL(property__get_length_all(properties), 1+2+strlen(value_expected));
		mosquitto_property_free_all(&properties);
	}
	CU_ASSERT_PTR_EQUAL(properties, NULL);
}

static void duplicate_string_helper(int command, uint8_t identifier)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = identifier;
	payload[2] = 0;
	payload[3] = 1; /* 1 length string */
	payload[4] = 'h';
	payload[5] = identifier;
	payload[6] = 0;
	payload[7] = 1;
	payload[8] = 'h';

	string_prop_read_helper(command, payload, 9, MOSQ_ERR_DUPLICATE_PROPERTY, identifier, "");
}

static void bad_string_helper(uint8_t identifier)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 6;
	payload[1] = identifier;
	payload[2] = 0;
	payload[3] = 3; /* 1 length string */
	payload[4] = 'h';
	payload[5] = 0; /* 0 in string not allowed */
	payload[6] = 'h';

	string_prop_read_helper(CMD_PUBLISH, payload, 7, MOSQ_ERR_MALFORMED_UTF8, identifier, "");
}

static void binary_prop_read_helper(
		int command,
		uint8_t *payload,
		uint32_t remaining_length,
		int rc_expected,
		uint8_t identifier,
		const uint8_t *value_expected,
		int len_expected)
{
	struct mosquitto__packet packet;
	mosquitto_property *properties;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = property__read_all(command, &packet, &properties);

	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(packet.pos, remaining_length);
	if(properties){
		CU_ASSERT_EQUAL(properties->identifier, identifier);
		CU_ASSERT_EQUAL(properties->value.bin.len, len_expected);
		CU_ASSERT_EQUAL(memcmp(properties->value.bin.v, value_expected, (size_t)len_expected), 0);
		CU_ASSERT_PTR_EQUAL(properties->next, NULL);
		CU_ASSERT_EQUAL(property__get_length_all(properties), 1+2+len_expected);
		mosquitto_property_free_all(&properties);
	}
	CU_ASSERT_PTR_EQUAL(properties, NULL);
}

static void duplicate_binary_helper(int command, uint8_t identifier)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = identifier;
	payload[2] = 0;
	payload[3] = 1; /* 2 length binary */
	payload[4] = 'h';
	payload[5] = identifier;
	payload[6] = 0;
	payload[7] = 1;
	payload[8] = 'h';

	string_prop_read_helper(command, payload, 9, MOSQ_ERR_DUPLICATE_PROPERTY, identifier, "");
}

static void string_pair_prop_read_helper(
		uint8_t *payload,
		uint32_t remaining_length,
		int rc_expected,
		uint8_t identifier,
		const char *name_expected,
		const char *value_expected,
		bool expect_multiple)
{
	struct mosquitto__packet packet;
	mosquitto_property *properties;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = property__read_all(CMD_CONNECT, &packet, &properties);

	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(packet.pos, remaining_length);
	if(properties){
		CU_ASSERT_EQUAL(properties->identifier, identifier);
		CU_ASSERT_EQUAL(properties->name.len, strlen(name_expected));
		CU_ASSERT_EQUAL(properties->value.s.len, strlen(value_expected));
		CU_ASSERT_STRING_EQUAL(properties->name.v, name_expected);
		CU_ASSERT_STRING_EQUAL(properties->value.s.v, value_expected);
		if(expect_multiple){
			CU_ASSERT_PTR_NOT_NULL(properties->next);
		}else{
			CU_ASSERT_PTR_NULL(properties->next);
			CU_ASSERT_EQUAL(property__get_length_all(properties), 1+2+strlen(name_expected)+2+strlen(value_expected));
		}
		mosquitto_property_free_all(&properties);
	}
	CU_ASSERT_PTR_NULL(properties);
}

static void varint_prop_read_helper(
		uint8_t *payload,
		uint32_t remaining_length,
		int rc_expected,
		uint8_t identifier,
		uint32_t value_expected)
{
	struct mosquitto__packet packet;
	mosquitto_property *properties;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = property__read_all(CMD_PUBLISH, &packet, &properties);

	CU_ASSERT_EQUAL(rc, rc_expected);
	if(properties){
		CU_ASSERT_EQUAL(properties->identifier, identifier);
		CU_ASSERT_EQUAL(properties->value.varint, value_expected);
		CU_ASSERT_PTR_NULL(properties->next);
		CU_ASSERT_EQUAL(property__get_length_all(properties), packet__varint_bytes(value_expected)+1);
		mosquitto_property_free_all(&properties);
	}
	CU_ASSERT_PTR_NULL(properties);
}

static void packet_helper_reason_string_user_property(int command)
{
	uint8_t payload[24] = {23,
		MQTT_PROP_REASON_STRING, 0, 6, 'r', 'e', 'a', 's', 'o', 'n',
		MQTT_PROP_USER_PROPERTY, 0, 4, 'n', 'a', 'm', 'e', 0, 5, 'v', 'a', 'l', 'u', 'e'};

	struct mosquitto__packet packet;
	mosquitto_property *properties, *p;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = sizeof(payload);;
	rc = property__read_all(command, &packet, &properties);

	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(properties);
	if(properties){
		CU_ASSERT_PTR_NOT_NULL(properties->next);
		p = properties;

		CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_REASON_STRING);
		CU_ASSERT_STRING_EQUAL(p->value.s.v, "reason");
		CU_ASSERT_EQUAL(p->value.s.len, strlen("reason"));

		p = p->next;
		if(p){
			CU_ASSERT_PTR_NULL(p->next);

			CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_USER_PROPERTY);
			CU_ASSERT_STRING_EQUAL(p->value.s.v, "value");
			CU_ASSERT_EQUAL(p->value.s.len, strlen("value"));
			CU_ASSERT_STRING_EQUAL(p->name.v, "name");
			CU_ASSERT_EQUAL(p->name.len, strlen("name"));
		}

		mosquitto_property_free_all(&properties);
	}
}

/* ========================================================================
 * NO PROPERTIES
 * ======================================================================== */

static void TEST_no_properties(void)
{
	struct mosquitto__packet packet;
	mosquitto_property *properties = NULL;
	uint8_t payload[5];
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	packet.remaining_length = 1;
	rc = property__read_all(CMD_CONNECT, &packet, &properties);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_EQUAL(properties, NULL);
	CU_ASSERT_EQUAL(packet.pos, 1);
}

static void TEST_truncated(void)
{
	struct mosquitto__packet packet;
	mosquitto_property *properties = NULL;
	uint8_t payload[5];
	int rc;

	/* Zero length packet */
	memset(&packet, 0, sizeof(struct mosquitto__packet));
	memset(payload, 0, sizeof(payload));
	packet.payload = payload;
	packet.remaining_length = 0;
	rc = property__read_all(CMD_CONNECT, &packet, &properties);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_PROTOCOL);
	CU_ASSERT_PTR_EQUAL(properties, NULL);
	CU_ASSERT_EQUAL(packet.pos, 0);

	/* Proplen > 0 but not enough data */
	memset(&packet, 0, sizeof(struct mosquitto__packet));
	memset(payload, 0, sizeof(payload));
	payload[0] = 2;
	packet.payload = payload;
	packet.remaining_length = 1;
	rc = property__read_all(CMD_CONNECT, &packet, &properties);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_PROTOCOL);
	CU_ASSERT_PTR_EQUAL(properties, NULL);
	CU_ASSERT_EQUAL(packet.pos, 1);

	/* Proplen > 0 but not enough data */
	memset(&packet, 0, sizeof(struct mosquitto__packet));
	memset(payload, 0, sizeof(payload));
	payload[0] = 4;
	payload[1] = MQTT_PROP_PAYLOAD_FORMAT_INDICATOR;
	packet.payload = payload;
	packet.remaining_length = 2;
	rc = property__read_all(CMD_CONNECT, &packet, &properties);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_PROTOCOL);
	CU_ASSERT_PTR_EQUAL(properties, NULL);
	CU_ASSERT_EQUAL(packet.pos, 2);
}

/* ========================================================================
 * INVALID PROPERTY ID
 * ======================================================================== */

static void TEST_invalid_property_id(void)
{
	struct mosquitto__packet packet;
	mosquitto_property *properties = NULL;
	uint8_t payload[5];
	int rc;

	/* ID = 0 */
	memset(&packet, 0, sizeof(struct mosquitto__packet));
	memset(payload, 0, sizeof(payload));
	payload[0] = 4;
	packet.payload = payload;
	packet.remaining_length = 2;
	rc = property__read_all(CMD_CONNECT, &packet, &properties);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_MALFORMED_PACKET);
	CU_ASSERT_PTR_EQUAL(properties, NULL);
	CU_ASSERT_EQUAL(packet.pos, 2);

	/* ID = 4 */
	memset(&packet, 0, sizeof(struct mosquitto__packet));
	memset(payload, 0, sizeof(payload));
	payload[0] = 4;
	payload[1] = 4;
	packet.payload = payload;
	packet.remaining_length = 2;
	rc = property__read_all(CMD_CONNECT, &packet, &properties);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_MALFORMED_PACKET);
	CU_ASSERT_PTR_EQUAL(properties, NULL);
	CU_ASSERT_EQUAL(packet.pos, 2);
}

/* ========================================================================
 * SINGLE PROPERTIES
 * ======================================================================== */

static void TEST_single_payload_format_indicator(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = MQTT_PROP_PAYLOAD_FORMAT_INDICATOR;
	payload[2] = 1;

	byte_prop_read_helper(CMD_PUBLISH, payload, 3, MOSQ_ERR_SUCCESS, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 1);
}

static void TEST_single_request_problem_information(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = MQTT_PROP_REQUEST_PROBLEM_INFORMATION;
	payload[2] = 1;

	byte_prop_read_helper(CMD_CONNECT, payload, 3, MOSQ_ERR_SUCCESS, MQTT_PROP_REQUEST_PROBLEM_INFORMATION, 1);
}

static void TEST_single_request_response_information(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = MQTT_PROP_REQUEST_RESPONSE_INFORMATION;
	payload[2] = 1;

	byte_prop_read_helper(CMD_CONNECT, payload, 3, MOSQ_ERR_SUCCESS, MQTT_PROP_REQUEST_RESPONSE_INFORMATION, 1);
}

static void TEST_single_maximum_qos(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = MQTT_PROP_MAXIMUM_QOS;
	payload[2] = 1;

	byte_prop_read_helper(CMD_CONNACK, payload, 3, MOSQ_ERR_SUCCESS, MQTT_PROP_MAXIMUM_QOS, 1);
}

static void TEST_single_retain_available(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = MQTT_PROP_RETAIN_AVAILABLE;
	payload[2] = 1;

	byte_prop_read_helper(CMD_CONNACK, payload, 3, MOSQ_ERR_SUCCESS, MQTT_PROP_RETAIN_AVAILABLE, 1);
}

static void TEST_single_wildcard_subscription_available(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = MQTT_PROP_WILDCARD_SUB_AVAILABLE;
	payload[2] = 0;

	byte_prop_read_helper(CMD_CONNACK, payload, 3, MOSQ_ERR_SUCCESS, MQTT_PROP_WILDCARD_SUB_AVAILABLE, 0);
}

static void TEST_single_subscription_identifier_available(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE;
	payload[2] = 0;

	byte_prop_read_helper(CMD_CONNACK, payload, 3, MOSQ_ERR_SUCCESS, MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE, 0);
}

static void TEST_single_shared_subscription_available(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 2; /* Proplen = Identifier + byte */
	payload[1] = MQTT_PROP_SHARED_SUB_AVAILABLE;
	payload[2] = 1;

	byte_prop_read_helper(CMD_CONNACK, payload, 3, MOSQ_ERR_SUCCESS, MQTT_PROP_SHARED_SUB_AVAILABLE, 1);
}

static void TEST_single_message_expiry_interval(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 5; /* Proplen = Identifier + int32 */
	payload[1] = MQTT_PROP_MESSAGE_EXPIRY_INTERVAL;
	payload[2] = 0x12;
	payload[3] = 0x23;
	payload[4] = 0x34;
	payload[5] = 0x45;

	int32_prop_read_helper(CMD_WILL, payload, 6, MOSQ_ERR_SUCCESS, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, 0x12233445);
}

static void TEST_single_session_expiry_interval(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 5; /* Proplen = Identifier + int32 */
	payload[1] = MQTT_PROP_SESSION_EXPIRY_INTERVAL;
	payload[2] = 0x45;
	payload[3] = 0x34;
	payload[4] = 0x23;
	payload[5] = 0x12;

	int32_prop_read_helper(CMD_CONNACK, payload, 6, MOSQ_ERR_SUCCESS, MQTT_PROP_SESSION_EXPIRY_INTERVAL, 0x45342312);
}

static void TEST_single_will_delay_interval(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 5; /* Proplen = Identifier + int32 */
	payload[1] = MQTT_PROP_WILL_DELAY_INTERVAL;
	payload[2] = 0x45;
	payload[3] = 0x34;
	payload[4] = 0x23;
	payload[5] = 0x12;

	int32_prop_read_helper(CMD_WILL, payload, 6, MOSQ_ERR_SUCCESS, MQTT_PROP_WILL_DELAY_INTERVAL, 0x45342312);
}

static void TEST_single_maximum_packet_size(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 5; /* Proplen = Identifier + int32 */
	payload[1] = MQTT_PROP_MAXIMUM_PACKET_SIZE;
	payload[2] = 0x45;
	payload[3] = 0x34;
	payload[4] = 0x23;
	payload[5] = 0x12;

	int32_prop_read_helper(CMD_CONNECT, payload, 6, MOSQ_ERR_SUCCESS, MQTT_PROP_MAXIMUM_PACKET_SIZE, 0x45342312);
}

static void TEST_single_server_keep_alive(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 3; /* Proplen = Identifier + int16 */
	payload[1] = MQTT_PROP_SERVER_KEEP_ALIVE;
	payload[2] = 0x45;
	payload[3] = 0x34;

	int16_prop_read_helper(CMD_CONNACK, payload, 4, MOSQ_ERR_SUCCESS, MQTT_PROP_SERVER_KEEP_ALIVE, 0x4534);
}

static void TEST_single_receive_maximum(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 3; /* Proplen = Identifier + int16 */
	payload[1] = MQTT_PROP_RECEIVE_MAXIMUM;
	payload[2] = 0x68;
	payload[3] = 0x42;

	int16_prop_read_helper(CMD_CONNACK, payload, 4, MOSQ_ERR_SUCCESS, MQTT_PROP_RECEIVE_MAXIMUM, 0x6842);
}

static void TEST_single_topic_alias_maximum(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 3; /* Proplen = Identifier + int16 */
	payload[1] = MQTT_PROP_TOPIC_ALIAS_MAXIMUM;
	payload[2] = 0x68;
	payload[3] = 0x42;

	int16_prop_read_helper(CMD_CONNECT, payload, 4, MOSQ_ERR_SUCCESS, MQTT_PROP_TOPIC_ALIAS_MAXIMUM, 0x6842);
}

static void TEST_single_topic_alias(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 3; /* Proplen = Identifier + int16 */
	payload[1] = MQTT_PROP_TOPIC_ALIAS;
	payload[2] = 0x68;
	payload[3] = 0x42;

	int16_prop_read_helper(CMD_PUBLISH, payload, 4, MOSQ_ERR_SUCCESS, MQTT_PROP_TOPIC_ALIAS, 0x6842);
}

static void TEST_single_content_type(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = MQTT_PROP_CONTENT_TYPE;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 'h';
	payload[5] = 'e';
	payload[6] = 'l';
	payload[7] = 'l';
	payload[8] = 'o';

	string_prop_read_helper(CMD_PUBLISH, payload, 9, MOSQ_ERR_SUCCESS, MQTT_PROP_CONTENT_TYPE, "hello");
}

static void TEST_single_response_topic(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = MQTT_PROP_RESPONSE_TOPIC;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 'h';
	payload[5] = 'e';
	payload[6] = 'l';
	payload[7] = 'l';
	payload[8] = 'o';

	string_prop_read_helper(CMD_WILL, payload, 9, MOSQ_ERR_SUCCESS, MQTT_PROP_RESPONSE_TOPIC, "hello");
}

static void TEST_single_assigned_client_identifier(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 'h';
	payload[5] = 'e';
	payload[6] = 'l';
	payload[7] = 'l';
	payload[8] = 'o';

	string_prop_read_helper(CMD_CONNACK, payload, 9, MOSQ_ERR_SUCCESS, MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER, "hello");
}

static void TEST_single_authentication_method(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = MQTT_PROP_AUTHENTICATION_METHOD;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 'h';
	payload[5] = 'e';
	payload[6] = 'l';
	payload[7] = 'l';
	payload[8] = 'o';

	string_prop_read_helper(CMD_AUTH, payload, 9, MOSQ_ERR_SUCCESS, MQTT_PROP_AUTHENTICATION_METHOD, "hello");
}

static void TEST_single_response_information(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = MQTT_PROP_RESPONSE_INFORMATION;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 'h';
	payload[5] = 'e';
	payload[6] = 'l';
	payload[7] = 'l';
	payload[8] = 'o';

	string_prop_read_helper(CMD_CONNACK, payload, 9, MOSQ_ERR_SUCCESS, MQTT_PROP_RESPONSE_INFORMATION, "hello");
}

static void TEST_single_server_reference(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = MQTT_PROP_SERVER_REFERENCE;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 'h';
	payload[5] = 'e';
	payload[6] = 'l';
	payload[7] = 'l';
	payload[8] = 'o';

	string_prop_read_helper(CMD_CONNACK, payload, 9, MOSQ_ERR_SUCCESS, MQTT_PROP_SERVER_REFERENCE, "hello");
}

static void TEST_single_reason_string(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = MQTT_PROP_REASON_STRING;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 'h';
	payload[5] = 'e';
	payload[6] = 'l';
	payload[7] = 'l';
	payload[8] = 'o';

	string_prop_read_helper(CMD_PUBCOMP, payload, 9, MOSQ_ERR_SUCCESS, MQTT_PROP_REASON_STRING, "hello");
}

static void TEST_single_correlation_data(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = MQTT_PROP_CORRELATION_DATA;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 1;
	payload[5] = 'e';
	payload[6] = 0;
	payload[7] = 'l';
	payload[8] = 9;

	binary_prop_read_helper(CMD_PUBLISH, payload, 9, MOSQ_ERR_SUCCESS, MQTT_PROP_CORRELATION_DATA, &payload[4], 5);
}

static void TEST_single_authentication_data(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 8;
	payload[1] = MQTT_PROP_AUTHENTICATION_DATA;
	payload[2] = 0x00;
	payload[3] = 0x05;
	payload[4] = 1;
	payload[5] = 'e';
	payload[6] = 0;
	payload[7] = 'l';
	payload[8] = 9;

	binary_prop_read_helper(CMD_CONNECT, payload, 9, MOSQ_ERR_SUCCESS, MQTT_PROP_AUTHENTICATION_DATA, &payload[4], 5);
}

static void TEST_single_user_property(void)
{
	uint8_t payload[20];

	payload[0] = 9;
	payload[1] = MQTT_PROP_USER_PROPERTY;
	payload[2] = 0;
	payload[3] = 2;
	payload[4] = 'z';
	payload[5] = 'a';
	payload[6] = 0;
	payload[7] = 2;
	payload[8] = 'b';
	payload[9] = 'c';

	string_pair_prop_read_helper(payload, 10, MOSQ_ERR_SUCCESS, MQTT_PROP_USER_PROPERTY, "za", "bc", false);
}

static void TEST_single_subscription_identifier(void)
{
	uint8_t payload[20];

	payload[0] = 2;
	payload[1] = MQTT_PROP_SUBSCRIPTION_IDENTIFIER;
	payload[2] = 0;
	varint_prop_read_helper(payload, 3, MOSQ_ERR_SUCCESS, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 0);

	payload[0] = 2;
	payload[1] = MQTT_PROP_SUBSCRIPTION_IDENTIFIER;
	payload[2] = 0x7F;
	varint_prop_read_helper(payload, 3, MOSQ_ERR_SUCCESS, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 127);

	payload[0] = 3;
	payload[1] = MQTT_PROP_SUBSCRIPTION_IDENTIFIER;
	payload[2] = 0x80;
	payload[3] = 0x01;
	varint_prop_read_helper(payload, 4, MOSQ_ERR_SUCCESS, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 128);

	payload[0] = 3;
	payload[1] = MQTT_PROP_SUBSCRIPTION_IDENTIFIER;
	payload[2] = 0xFF;
	payload[3] = 0x7F;
	varint_prop_read_helper(payload, 4, MOSQ_ERR_SUCCESS, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 16383);

	payload[0] = 4;
	payload[1] = MQTT_PROP_SUBSCRIPTION_IDENTIFIER;
	payload[2] = 0x80;
	payload[3] = 0x80;
	payload[4] = 0x01;
	varint_prop_read_helper(payload, 5, MOSQ_ERR_SUCCESS, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 16384);

	payload[0] = 4;
	payload[1] = MQTT_PROP_SUBSCRIPTION_IDENTIFIER;
	payload[2] = 0xFF;
	payload[3] = 0xFF;
	payload[4] = 0x7F;
	varint_prop_read_helper(payload, 5, MOSQ_ERR_SUCCESS, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 2097151);

	payload[0] = 5;
	payload[1] = MQTT_PROP_SUBSCRIPTION_IDENTIFIER;
	payload[2] = 0x80;
	payload[3] = 0x80;
	payload[4] = 0x80;
	payload[5] = 0x01;
	varint_prop_read_helper(payload, 6, MOSQ_ERR_SUCCESS, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 2097152);


	payload[0] = 5;
	payload[1] = MQTT_PROP_SUBSCRIPTION_IDENTIFIER;
	payload[2] = 0xFF;
	payload[3] = 0xFF;
	payload[4] = 0xFF;
	payload[5] = 0x7F;
	varint_prop_read_helper(payload, 6, MOSQ_ERR_SUCCESS, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 268435455);
}

/* ========================================================================
 * DUPLICATE PROPERTIES
 * ======================================================================== */

static void TEST_duplicate_payload_format_indicator(void)
{
	duplicate_byte_helper(CMD_PUBLISH, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR);
}

static void TEST_duplicate_request_problem_information(void)
{
	duplicate_byte_helper(CMD_CONNECT, MQTT_PROP_REQUEST_PROBLEM_INFORMATION);
}

static void TEST_duplicate_request_response_information(void)
{
	duplicate_byte_helper(CMD_CONNECT, MQTT_PROP_REQUEST_RESPONSE_INFORMATION);
}

static void TEST_duplicate_maximum_qos(void)
{
	duplicate_byte_helper(CMD_CONNACK, MQTT_PROP_MAXIMUM_QOS);
}

static void TEST_duplicate_retain_available(void)
{
	duplicate_byte_helper(CMD_CONNACK, MQTT_PROP_RETAIN_AVAILABLE);
}

static void TEST_duplicate_wildcard_subscription_available(void)
{
	duplicate_byte_helper(CMD_CONNACK, MQTT_PROP_WILDCARD_SUB_AVAILABLE);
}

static void TEST_duplicate_subscription_identifier_available(void)
{
	duplicate_byte_helper(CMD_CONNACK, MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE);
}

static void TEST_duplicate_shared_subscription_available(void)
{
	duplicate_byte_helper(CMD_CONNACK, MQTT_PROP_SHARED_SUB_AVAILABLE);
}

static void TEST_duplicate_message_expiry_interval(void)
{
	duplicate_int32_helper(CMD_PUBLISH, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL);
}

static void TEST_duplicate_session_expiry_interval(void)
{
	duplicate_int32_helper(CMD_DISCONNECT, MQTT_PROP_SESSION_EXPIRY_INTERVAL);
}

static void TEST_duplicate_will_delay_interval(void)
{
	duplicate_int32_helper(CMD_WILL, MQTT_PROP_WILL_DELAY_INTERVAL);
}

static void TEST_duplicate_maximum_packet_size(void)
{
	duplicate_int32_helper(CMD_CONNECT, MQTT_PROP_MAXIMUM_PACKET_SIZE);
}

static void TEST_duplicate_server_keep_alive(void)
{
	duplicate_int16_helper(CMD_CONNACK, MQTT_PROP_SERVER_KEEP_ALIVE);
}

static void TEST_duplicate_receive_maximum(void)
{
	duplicate_int16_helper(CMD_CONNACK, MQTT_PROP_RECEIVE_MAXIMUM);
}

static void TEST_duplicate_topic_alias_maximum(void)
{
	duplicate_int16_helper(CMD_CONNECT, MQTT_PROP_TOPIC_ALIAS_MAXIMUM);
}

static void TEST_duplicate_topic_alias(void)
{
	duplicate_int16_helper(CMD_PUBLISH, MQTT_PROP_TOPIC_ALIAS);
}

static void TEST_duplicate_content_type(void)
{
	duplicate_string_helper(CMD_PUBLISH, MQTT_PROP_CONTENT_TYPE);
}

static void TEST_duplicate_response_topic(void)
{
	duplicate_string_helper(CMD_PUBLISH, MQTT_PROP_RESPONSE_TOPIC);
}

static void TEST_duplicate_assigned_client_identifier(void)
{
	duplicate_string_helper(CMD_CONNACK, MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER);
}

static void TEST_duplicate_authentication_method(void)
{
	duplicate_string_helper(CMD_AUTH, MQTT_PROP_AUTHENTICATION_METHOD);
}

static void TEST_duplicate_response_information(void)
{
	duplicate_string_helper(CMD_CONNACK, MQTT_PROP_RESPONSE_INFORMATION);
}

static void TEST_duplicate_server_reference(void)
{
	duplicate_string_helper(CMD_CONNACK, MQTT_PROP_SERVER_REFERENCE);
}

static void TEST_duplicate_reason_string(void)
{
	duplicate_string_helper(CMD_PUBACK, MQTT_PROP_REASON_STRING);
}

static void TEST_duplicate_correlation_data(void)
{
	duplicate_binary_helper(CMD_PUBLISH, MQTT_PROP_CORRELATION_DATA);
}

static void TEST_duplicate_authentication_data(void)
{
	duplicate_binary_helper(CMD_CONNACK, MQTT_PROP_AUTHENTICATION_DATA);
}

static void TEST_duplicate_user_property(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 18; /* Proplen = (Identifier + byte)*2 */
	payload[1] = MQTT_PROP_USER_PROPERTY;
	payload[2] = 0;
	payload[3] = 2;
	payload[4] = 'a';
	payload[5] = 'b';
	payload[6] = 0;
	payload[7] = 2;
	payload[8] = 'g';
	payload[9] = 'h';
	payload[10] = MQTT_PROP_USER_PROPERTY;
	payload[11] = 0;
	payload[12] = 2;
	payload[13] = 'c';
	payload[14] = 'd';
	payload[15] = 0;
	payload[16] = 2;
	payload[17] = 'e';
	payload[18] = 'f';

	string_pair_prop_read_helper(payload, 19, MOSQ_ERR_SUCCESS, MQTT_PROP_USER_PROPERTY, "ab", "gh", true);
}

static void TEST_duplicate_subscription_identifier(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 4; /* Proplen = (Identifier + byte)*2 */
	payload[1] = MQTT_PROP_SUBSCRIPTION_IDENTIFIER;
	payload[2] = 0x80;
	payload[3] = 0x02;
	payload[4] = MQTT_PROP_SUBSCRIPTION_IDENTIFIER;
	payload[5] = 0x04;

	varint_prop_read_helper(payload, 5, MOSQ_ERR_PROTOCOL, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 0);
}

/* ========================================================================
 * BAD PROPERTY VALUES
 * ======================================================================== */

static void TEST_bad_request_problem_information(void)
{
	bad_byte_helper(CMD_CONNECT, MQTT_PROP_REQUEST_PROBLEM_INFORMATION);
}

static void TEST_bad_request_response_information(void)
{
	bad_byte_helper(CMD_CONNECT, MQTT_PROP_REQUEST_RESPONSE_INFORMATION);
}

static void TEST_bad_maximum_qos(void)
{
	bad_byte_helper(CMD_CONNACK, MQTT_PROP_MAXIMUM_QOS);
}

static void TEST_bad_retain_available(void)
{
	bad_byte_helper(CMD_CONNACK, MQTT_PROP_RETAIN_AVAILABLE);
}

static void TEST_bad_wildcard_sub_available(void)
{
	bad_byte_helper(CMD_CONNACK, MQTT_PROP_WILDCARD_SUB_AVAILABLE);
}

static void TEST_bad_subscription_id_available(void)
{
	bad_byte_helper(CMD_CONNACK, MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE);
}

static void TEST_bad_shared_sub_available(void)
{
	bad_byte_helper(CMD_CONNACK, MQTT_PROP_SHARED_SUB_AVAILABLE);
}

static void TEST_bad_maximum_packet_size(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 5; /* Proplen = Identifier + int32 */
	payload[1] = MQTT_PROP_MAXIMUM_PACKET_SIZE;
	payload[2] = 0;
	payload[3] = 0;
	payload[4] = 0;
	payload[5] = 0; /* 0 is invalid */

	int32_prop_read_helper(CMD_CONNACK, payload, 6, MOSQ_ERR_PROTOCOL, MQTT_PROP_MAXIMUM_PACKET_SIZE, 0);
}

static void TEST_bad_receive_maximum(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 3; /* Proplen = Identifier + int16 */
	payload[1] = MQTT_PROP_RECEIVE_MAXIMUM;
	payload[2] = 0;
	payload[3] = 0; /* 0 is invalid */

	int32_prop_read_helper(CMD_CONNECT, payload, 4, MOSQ_ERR_PROTOCOL, MQTT_PROP_RECEIVE_MAXIMUM, 0);
}

static void TEST_bad_topic_alias(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 3; /* Proplen = Identifier + int16 */
	payload[1] = MQTT_PROP_TOPIC_ALIAS;
	payload[2] = 0;
	payload[3] = 0; /* 0 is invalid */

	int32_prop_read_helper(CMD_PUBLISH, payload, 4, MOSQ_ERR_PROTOCOL, MQTT_PROP_TOPIC_ALIAS, 0);
}

static void TEST_bad_content_type(void)
{
	bad_string_helper(MQTT_PROP_CONTENT_TYPE);
}

static void TEST_bad_subscription_identifier(void)
{
	uint8_t payload[20];

	memset(&payload, 0, sizeof(payload));
	payload[0] = 6;
	payload[1] = MQTT_PROP_SUBSCRIPTION_IDENTIFIER;
	payload[2] = 0xFF;
	payload[3] = 0xFF;
	payload[4] = 0xFF;
	payload[5] = 0xFF;
	payload[6] = 0x01;

	varint_prop_read_helper(payload, 7, MOSQ_ERR_PROTOCOL, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 0);
}

/* ========================================================================
 * CONTROL PACKET TESTS
 * ======================================================================== */

static void TEST_packet_connect(void)
{
	uint8_t payload[] = {0,
		MQTT_PROP_SESSION_EXPIRY_INTERVAL, 0x12, 0x45, 0x00, 0x00,
		MQTT_PROP_RECEIVE_MAXIMUM, 0x00, 0x05,
		MQTT_PROP_MAXIMUM_PACKET_SIZE, 0x12, 0x45, 0x00, 0x00,
		MQTT_PROP_TOPIC_ALIAS_MAXIMUM, 0x00, 0x02,
		MQTT_PROP_REQUEST_PROBLEM_INFORMATION, 1,
		MQTT_PROP_REQUEST_RESPONSE_INFORMATION, 1,
		MQTT_PROP_USER_PROPERTY, 0, 4, 'n', 'a', 'm', 'e', 0, 5, 'v', 'a', 'l', 'u', 'e',
		MQTT_PROP_AUTHENTICATION_METHOD, 0x00, 0x04, 'n', 'o', 'n', 'e',
		MQTT_PROP_AUTHENTICATION_DATA, 0x00, 0x02, 1, 2};

	struct mosquitto__packet packet;
	mosquitto_property *properties, *p;
	int rc;

	payload[0] = sizeof(payload)-1;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = sizeof(payload);;
	rc = property__read_all(CMD_CONNECT, &packet, &properties);

	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	p = properties;
	CU_ASSERT_PTR_NOT_NULL(properties);
	if(p){
		CU_ASSERT_PTR_NOT_NULL(p->next);
		CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_SESSION_EXPIRY_INTERVAL);
		CU_ASSERT_EQUAL(p->value.i32, 0x12450000);

		p = p->next;
		CU_ASSERT_PTR_NOT_NULL(p);
		if(p){
			CU_ASSERT_PTR_NOT_NULL(p->next);
			CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_RECEIVE_MAXIMUM);
			CU_ASSERT_EQUAL(p->value.i16, 0x0005);

			p = p->next;
			CU_ASSERT_PTR_NOT_NULL(p);
			if(p){
				CU_ASSERT_PTR_NOT_NULL(p->next);
				CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_MAXIMUM_PACKET_SIZE);
				CU_ASSERT_EQUAL(p->value.i32, 0x12450000);

				p = p->next;
				CU_ASSERT_PTR_NOT_NULL(p);
				if(p){
					CU_ASSERT_PTR_NOT_NULL(p->next);
					CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_TOPIC_ALIAS_MAXIMUM);
					CU_ASSERT_EQUAL(p->value.i16, 0x0002);

					p = p->next;
					CU_ASSERT_PTR_NOT_NULL(p);
					if(p){
						CU_ASSERT_PTR_NOT_NULL(p->next);
						CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_REQUEST_PROBLEM_INFORMATION);
						CU_ASSERT_EQUAL(p->value.i8, 1);

						p = p->next;
						CU_ASSERT_PTR_NOT_NULL(p);
						if(p){
							CU_ASSERT_PTR_NOT_NULL(p->next);
							CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_REQUEST_RESPONSE_INFORMATION);
							CU_ASSERT_EQUAL(p->value.i8, 1);

							p = p->next;
							CU_ASSERT_PTR_NOT_NULL(p);
							if(p){
								CU_ASSERT_PTR_NOT_NULL(p->next);
								CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_USER_PROPERTY);
								CU_ASSERT_STRING_EQUAL(p->value.s.v, "value");
								CU_ASSERT_EQUAL(p->value.s.len, strlen("value"));
								CU_ASSERT_STRING_EQUAL(p->name.v, "name");
								CU_ASSERT_EQUAL(p->name.len, strlen("name"));

								p = p->next;
								CU_ASSERT_PTR_NOT_NULL(p);
								if(p){
									CU_ASSERT_PTR_NOT_NULL(p->next);
									CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_AUTHENTICATION_METHOD);
									CU_ASSERT_STRING_EQUAL(p->value.s.v, "none");
									CU_ASSERT_EQUAL(p->value.s.len, strlen("none"));

									p = p->next;
									CU_ASSERT_PTR_NOT_NULL(p);
									if(p){
										CU_ASSERT_PTR_NULL(p->next);
										CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_AUTHENTICATION_DATA);
										CU_ASSERT_EQUAL(p->value.bin.v[0], 1);
										CU_ASSERT_EQUAL(p->value.bin.v[1], 2);
										CU_ASSERT_EQUAL(p->value.s.len, 2);
									}
								}
							}
						}
					}
				}
			}
		}
	}

	mosquitto_property_free_all(&properties);
}

static void TEST_packet_connack(void)
{
	uint8_t payload[] = {0,
		MQTT_PROP_SESSION_EXPIRY_INTERVAL, 0x12, 0x45, 0x00, 0x00,
		MQTT_PROP_RECEIVE_MAXIMUM, 0x00, 0x05,
		MQTT_PROP_MAXIMUM_QOS, 1,
		MQTT_PROP_RETAIN_AVAILABLE, 0,
		MQTT_PROP_MAXIMUM_PACKET_SIZE, 0x12, 0x45, 0x00, 0x00,
		MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER, 0x00, 0x02, 'a', 'b',
		MQTT_PROP_TOPIC_ALIAS_MAXIMUM, 0x00, 0x02,
		MQTT_PROP_REASON_STRING, 0, 6, 'r', 'e', 'a', 's', 'o', 'n',
		MQTT_PROP_USER_PROPERTY, 0, 4, 'n', 'a', 'm', 'e', 0, 5, 'v', 'a', 'l', 'u', 'e',
		MQTT_PROP_WILDCARD_SUB_AVAILABLE, 0,
		MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE, 0,
		MQTT_PROP_SHARED_SUB_AVAILABLE, 0,
		MQTT_PROP_SERVER_KEEP_ALIVE, 0x00, 0xFF,
		MQTT_PROP_RESPONSE_INFORMATION, 0x00, 0x03, 'r', 's', 'p',
		MQTT_PROP_SERVER_REFERENCE, 0x00, 0x04, 's', 'e', 'r', 'v',
		MQTT_PROP_AUTHENTICATION_METHOD, 0x00, 0x04, 'n', 'o', 'n', 'e',
		MQTT_PROP_AUTHENTICATION_DATA, 0x00, 0x02, 1, 2};

	struct mosquitto__packet packet;
	mosquitto_property *properties, *p;
	int rc;

	payload[0] = sizeof(payload)-1;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = sizeof(payload);;
	rc = property__read_all(CMD_CONNACK, &packet, &properties);

	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(properties);
	p = properties;

	CU_ASSERT_PTR_NOT_NULL(p);
	if(p){
		CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_SESSION_EXPIRY_INTERVAL);
		CU_ASSERT_EQUAL(p->value.i32, 0x12450000);

		p = p->next;
		CU_ASSERT_PTR_NOT_NULL(p);
		if(p){
			CU_ASSERT_PTR_NOT_NULL(p->next);
			CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_RECEIVE_MAXIMUM);
			CU_ASSERT_EQUAL(p->value.i16, 0x0005);

			p = p->next;
			CU_ASSERT_PTR_NOT_NULL(p);
			if(p){
				CU_ASSERT_PTR_NOT_NULL(p->next);
				CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_MAXIMUM_QOS);
				CU_ASSERT_EQUAL(p->value.i8, 1);

				p = p->next;
				CU_ASSERT_PTR_NOT_NULL(p);
				if(p){
					CU_ASSERT_PTR_NOT_NULL(p->next);
					CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_RETAIN_AVAILABLE);
					CU_ASSERT_EQUAL(p->value.i8, 0);

					p = p->next;
					CU_ASSERT_PTR_NOT_NULL(p);
					if(p){
						CU_ASSERT_PTR_NOT_NULL(p->next);
						CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_MAXIMUM_PACKET_SIZE);
						CU_ASSERT_EQUAL(p->value.i32, 0x12450000);

						p = p->next;
						CU_ASSERT_PTR_NOT_NULL(p);
						if(p){
							CU_ASSERT_PTR_NOT_NULL(p->next);
							CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER);
							CU_ASSERT_STRING_EQUAL(p->value.s.v, "ab");
							CU_ASSERT_EQUAL(p->value.s.len, strlen("ab"));

							p = p->next;
							CU_ASSERT_PTR_NOT_NULL(p);
							if(p){
								CU_ASSERT_PTR_NOT_NULL(p->next);
								CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_TOPIC_ALIAS_MAXIMUM);
								CU_ASSERT_EQUAL(p->value.i16, 0x0002);

								p = p->next;
								CU_ASSERT_PTR_NOT_NULL(p);
								if(p){
									CU_ASSERT_PTR_NOT_NULL(p->next);
									CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_REASON_STRING);
									CU_ASSERT_STRING_EQUAL(p->value.s.v, "reason");
									CU_ASSERT_EQUAL(p->value.s.len, strlen("reason"));

									p = p->next;
									CU_ASSERT_PTR_NOT_NULL(p);
									if(p){
										CU_ASSERT_PTR_NOT_NULL(p->next);
										CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_USER_PROPERTY);
										CU_ASSERT_STRING_EQUAL(p->value.s.v, "value");
										CU_ASSERT_EQUAL(p->value.s.len, strlen("value"));
										CU_ASSERT_STRING_EQUAL(p->name.v, "name");
										CU_ASSERT_EQUAL(p->name.len, strlen("name"));

										p = p->next;
										CU_ASSERT_PTR_NOT_NULL(p);
										if(p){
											CU_ASSERT_PTR_NOT_NULL(p->next);
											CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_WILDCARD_SUB_AVAILABLE);
											CU_ASSERT_EQUAL(p->value.i8, 0);

											p = p->next;
											CU_ASSERT_PTR_NOT_NULL(p);
											if(p){
												CU_ASSERT_PTR_NOT_NULL(p->next);
												CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_SUBSCRIPTION_ID_AVAILABLE);
												CU_ASSERT_EQUAL(p->value.i8, 0);

												p = p->next;
												CU_ASSERT_PTR_NOT_NULL(p);
												if(p){
													CU_ASSERT_PTR_NOT_NULL(p->next);
													CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_SHARED_SUB_AVAILABLE);
													CU_ASSERT_EQUAL(p->value.i8, 0);

													p = p->next;
													CU_ASSERT_PTR_NOT_NULL(p);
													if(p){
														CU_ASSERT_PTR_NOT_NULL(p->next);
														CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_SERVER_KEEP_ALIVE);
														CU_ASSERT_EQUAL(p->value.i16, 0x00FF);

														p = p->next;
														CU_ASSERT_PTR_NOT_NULL(p);
														if(p){
															CU_ASSERT_PTR_NOT_NULL(p->next);
															CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_RESPONSE_INFORMATION);
															CU_ASSERT_STRING_EQUAL(p->value.s.v, "rsp");
															CU_ASSERT_EQUAL(p->value.s.len, strlen("rsp"));

															p = p->next;
															CU_ASSERT_PTR_NOT_NULL(p);
															if(p){
																CU_ASSERT_PTR_NOT_NULL(p->next);
																CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_SERVER_REFERENCE);
																CU_ASSERT_STRING_EQUAL(p->value.s.v, "serv");
																CU_ASSERT_EQUAL(p->value.s.len, strlen("serv"));

																p = p->next;
																CU_ASSERT_PTR_NOT_NULL(p);
																if(p){
																	CU_ASSERT_PTR_NOT_NULL(p->next);
																	CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_AUTHENTICATION_METHOD);
																	CU_ASSERT_STRING_EQUAL(p->value.s.v, "none");
																	CU_ASSERT_EQUAL(p->value.s.len, strlen("none"));

																	p = p->next;
																	CU_ASSERT_PTR_NOT_NULL(p);
																	if(p){
																		CU_ASSERT_PTR_NULL(p->next);
																		CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_AUTHENTICATION_DATA);
																		CU_ASSERT_EQUAL(p->value.bin.v[0], 1);
																		CU_ASSERT_EQUAL(p->value.bin.v[1], 2);
																		CU_ASSERT_EQUAL(p->value.s.len, 2);
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	mosquitto_property_free_all(&properties);
}

static void TEST_packet_publish(void)
{
	uint8_t payload[] = {0,
		MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 1,
		MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, 0x12, 0x45, 0x00, 0x00,
		MQTT_PROP_TOPIC_ALIAS, 0x00, 0x02,
		MQTT_PROP_RESPONSE_TOPIC, 0, 6, 'r', 'e', 's', 'p', 'o', 'n',
		MQTT_PROP_CORRELATION_DATA, 0x00, 0x02, 1, 2,
		MQTT_PROP_USER_PROPERTY, 0, 4, 'n', 'a', 'm', 'e', 0, 5, 'v', 'a', 'l', 'u', 'e',
		MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 0x04,
		MQTT_PROP_CONTENT_TYPE, 0, 5, 'e', 'm', 'p', 't', 'y'};

	struct mosquitto__packet packet;
	mosquitto_property *properties, *p;
	int rc;

	payload[0] = sizeof(payload)-1;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = sizeof(payload);;
	rc = property__read_all(CMD_PUBLISH, &packet, &properties);

	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	p = properties;

	CU_ASSERT_PTR_NOT_NULL(p);
	if(p){
		CU_ASSERT_PTR_NOT_NULL(p->next);
		CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR);
		CU_ASSERT_EQUAL(p->value.i8, 1);

		p = p->next;
		CU_ASSERT_PTR_NOT_NULL(p);
		if(p){
			CU_ASSERT_PTR_NOT_NULL(p->next);
			CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL);
			CU_ASSERT_EQUAL(p->value.i32, 0x12450000);

			p = p->next;
			CU_ASSERT_PTR_NOT_NULL(p);
			if(p){
				CU_ASSERT_PTR_NOT_NULL(p->next);
				CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_TOPIC_ALIAS);
				CU_ASSERT_EQUAL(p->value.i16, 0x0002);

				p = p->next;
				CU_ASSERT_PTR_NOT_NULL(p);
				if(p){
					CU_ASSERT_PTR_NOT_NULL(p->next);
					CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_RESPONSE_TOPIC);
					CU_ASSERT_STRING_EQUAL(p->value.s.v, "respon");
					CU_ASSERT_EQUAL(p->value.s.len, strlen("respon"));

					p = p->next;
					CU_ASSERT_PTR_NOT_NULL(p);
					if(p){
						CU_ASSERT_PTR_NOT_NULL(p->next);
						CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_CORRELATION_DATA);
						CU_ASSERT_EQUAL(p->value.bin.v[0], 1);
						CU_ASSERT_EQUAL(p->value.bin.v[1], 2);
						CU_ASSERT_EQUAL(p->value.bin.len, 2);

						p = p->next;
						CU_ASSERT_PTR_NOT_NULL(p);
						if(p){
							CU_ASSERT_PTR_NOT_NULL(p->next);
							CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_USER_PROPERTY);
							CU_ASSERT_STRING_EQUAL(p->value.s.v, "value");
							CU_ASSERT_EQUAL(p->value.s.len, strlen("value"));
							CU_ASSERT_STRING_EQUAL(p->name.v, "name");
							CU_ASSERT_EQUAL(p->name.len, strlen("name"));

							p = p->next;
							CU_ASSERT_PTR_NOT_NULL(p);
							if(p){
								CU_ASSERT_PTR_NOT_NULL(p->next);
								CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_SUBSCRIPTION_IDENTIFIER);
								CU_ASSERT_EQUAL(p->value.varint, 0x00000004);

								p = p->next;
								CU_ASSERT_PTR_NOT_NULL(p);
								if(p){
									CU_ASSERT_PTR_NULL(p->next);
									CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_CONTENT_TYPE);
									CU_ASSERT_STRING_EQUAL(p->value.s.v, "empty");
									CU_ASSERT_EQUAL(p->value.s.len, strlen("empty"));
								}
							}
						}
					}
				}
			}
		}
	}

	mosquitto_property_free_all(&properties);
}

static void TEST_packet_puback(void)
{
	packet_helper_reason_string_user_property(CMD_PUBACK);
}

static void TEST_packet_pubrec(void)
{
	packet_helper_reason_string_user_property(CMD_PUBREC);
}

static void TEST_packet_pubrel(void)
{
	packet_helper_reason_string_user_property(CMD_PUBREL);
}

static void TEST_packet_pubcomp(void)
{
	packet_helper_reason_string_user_property(CMD_PUBCOMP);
}

static void TEST_packet_subscribe(void)
{
	uint8_t payload[] = {0,
		MQTT_PROP_USER_PROPERTY, 0, 4, 'n', 'a', 'm', 'e', 0, 5, 'v', 'a', 'l', 'u', 'e',
		MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 0x04};

	struct mosquitto__packet packet;
	mosquitto_property *properties, *p;
	int rc;

	payload[0] = sizeof(payload)-1;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = sizeof(payload);;
	rc = property__read_all(CMD_SUBSCRIBE, &packet, &properties);

	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	p = properties;

	CU_ASSERT_PTR_NOT_NULL(p);
	if(p){
		CU_ASSERT_PTR_NOT_NULL(p->next);
		CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_USER_PROPERTY);
		CU_ASSERT_STRING_EQUAL(p->value.s.v, "value");
		CU_ASSERT_EQUAL(p->value.s.len, strlen("value"));
		CU_ASSERT_STRING_EQUAL(p->name.v, "name");
		CU_ASSERT_EQUAL(p->name.len, strlen("name"));

		p = p->next;
		CU_ASSERT_PTR_NOT_NULL(p);
		if(p){
			CU_ASSERT_PTR_NULL(p->next);
			CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_SUBSCRIPTION_IDENTIFIER);
			CU_ASSERT_EQUAL(p->value.varint, 0x00000004);
		}
	}

	mosquitto_property_free_all(&properties);
}

static void TEST_packet_suback(void)
{
	packet_helper_reason_string_user_property(CMD_SUBACK);
}

static void TEST_packet_unsubscribe(void)
{
	uint8_t payload[] = {0,
		MQTT_PROP_USER_PROPERTY, 0, 4, 'n', 'a', 'm', 'e', 0, 5, 'v', 'a', 'l', 'u', 'e'};

	struct mosquitto__packet packet;
	mosquitto_property *properties, *p;
	int rc;

	payload[0] = sizeof(payload)-1;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = sizeof(payload);;
	rc = property__read_all(CMD_UNSUBSCRIBE, &packet, &properties);

	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	p = properties;

	CU_ASSERT_PTR_NOT_NULL(p);
	if(p){
		CU_ASSERT_PTR_NULL(p->next);
		CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_USER_PROPERTY);
		CU_ASSERT_STRING_EQUAL(p->value.s.v, "value");
		CU_ASSERT_EQUAL(p->value.s.len, strlen("value"));
		CU_ASSERT_STRING_EQUAL(p->name.v, "name");
		CU_ASSERT_EQUAL(p->name.len, strlen("name"));
	}

	mosquitto_property_free_all(&properties);
}

static void TEST_packet_unsuback(void)
{
	packet_helper_reason_string_user_property(CMD_UNSUBACK);
}

static void TEST_packet_disconnect(void)
{
	uint8_t payload[] = {0,
		MQTT_PROP_SESSION_EXPIRY_INTERVAL, 0x12, 0x45, 0x00, 0x00,
		MQTT_PROP_REASON_STRING, 0, 6, 'r', 'e', 'a', 's', 'o', 'n',
		MQTT_PROP_USER_PROPERTY, 0, 4, 'n', 'a', 'm', 'e', 0, 5, 'v', 'a', 'l', 'u', 'e'};

	struct mosquitto__packet packet;
	mosquitto_property *properties, *p;
	int rc;

	payload[0] = sizeof(payload)-1;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = sizeof(payload);;
	rc = property__read_all(CMD_DISCONNECT, &packet, &properties);

	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	p = properties;

	CU_ASSERT_PTR_NOT_NULL(p);
	if(p){
		CU_ASSERT_PTR_NOT_NULL(p->next);
		CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_SESSION_EXPIRY_INTERVAL);
		CU_ASSERT_EQUAL(p->value.i32, 0x12450000);

		p = p->next;
		CU_ASSERT_PTR_NOT_NULL(p);
		if(p){
			CU_ASSERT_PTR_NOT_NULL(p->next);
			CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_REASON_STRING);
			CU_ASSERT_STRING_EQUAL(p->value.s.v, "reason");
			CU_ASSERT_EQUAL(p->value.s.len, strlen("reason"));

			p = p->next;
			CU_ASSERT_PTR_NOT_NULL(p);
			if(p){
				CU_ASSERT_PTR_NULL(p->next);
				CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_USER_PROPERTY);
				CU_ASSERT_STRING_EQUAL(p->value.s.v, "value");
				CU_ASSERT_EQUAL(p->value.s.len, strlen("value"));
				CU_ASSERT_STRING_EQUAL(p->name.v, "name");
				CU_ASSERT_EQUAL(p->name.len, strlen("name"));
			}
		}
	}

	mosquitto_property_free_all(&properties);
}

static void TEST_packet_auth(void)
{
	uint8_t payload[] = {0,
		MQTT_PROP_AUTHENTICATION_METHOD, 0x00, 0x04, 'n', 'o', 'n', 'e',
		MQTT_PROP_AUTHENTICATION_DATA, 0x00, 0x02, 1, 2,
		MQTT_PROP_REASON_STRING, 0, 6, 'r', 'e', 'a', 's', 'o', 'n',
		MQTT_PROP_USER_PROPERTY, 0, 4, 'n', 'a', 'm', 'e', 0, 5, 'v', 'a', 'l', 'u', 'e'};

	struct mosquitto__packet packet;
	mosquitto_property *properties, *p;
	int rc;

	payload[0] = sizeof(payload)-1;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = sizeof(payload);;
	rc = property__read_all(CMD_AUTH, &packet, &properties);

	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	p = properties;

	CU_ASSERT_PTR_NOT_NULL(p);
	if(p){
		CU_ASSERT_PTR_NOT_NULL(p->next);
		CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_AUTHENTICATION_METHOD);
		CU_ASSERT_STRING_EQUAL(p->value.s.v, "none");
		CU_ASSERT_EQUAL(p->value.s.len, strlen("none"));

		p = p->next;
		CU_ASSERT_PTR_NOT_NULL(p);
		if(p){
			CU_ASSERT_PTR_NOT_NULL(p->next);
			CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_AUTHENTICATION_DATA);
			CU_ASSERT_EQUAL(p->value.bin.v[0], 1);
			CU_ASSERT_EQUAL(p->value.bin.v[1], 2);
			CU_ASSERT_EQUAL(p->value.s.len, 2);

			p = p->next;
			CU_ASSERT_PTR_NOT_NULL(p);
			if(p){
				CU_ASSERT_PTR_NOT_NULL(p->next);
				CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_REASON_STRING);
				CU_ASSERT_STRING_EQUAL(p->value.s.v, "reason");
				CU_ASSERT_EQUAL(p->value.s.len, strlen("reason"));

				p = p->next;
				CU_ASSERT_PTR_NOT_NULL(p);
				if(p){
					CU_ASSERT_PTR_NULL(p->next);
					CU_ASSERT_EQUAL(p->identifier, MQTT_PROP_USER_PROPERTY);
					CU_ASSERT_STRING_EQUAL(p->value.s.v, "value");
					CU_ASSERT_EQUAL(p->value.s.len, strlen("value"));
					CU_ASSERT_STRING_EQUAL(p->name.v, "name");
					CU_ASSERT_EQUAL(p->name.len, strlen("name"));
				}
			}
		}
	}

	mosquitto_property_free_all(&properties);
}


/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */

int init_property_read_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("Property read", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit Property read test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Truncated packet", TEST_truncated)
			|| !CU_add_test(test_suite, "Invalid property ID", TEST_invalid_property_id)
			|| !CU_add_test(test_suite, "No properties", TEST_no_properties)
			|| !CU_add_test(test_suite, "Single Payload Format Indicator", TEST_single_payload_format_indicator)
			|| !CU_add_test(test_suite, "Single Request Problem Information", TEST_single_request_problem_information)
			|| !CU_add_test(test_suite, "Single Request Response Information", TEST_single_request_response_information)
			|| !CU_add_test(test_suite, "Single Maximum QoS", TEST_single_maximum_qos)
			|| !CU_add_test(test_suite, "Single Retain Available", TEST_single_retain_available)
			|| !CU_add_test(test_suite, "Single Wildcard Subscription Available", TEST_single_wildcard_subscription_available)
			|| !CU_add_test(test_suite, "Single Subscription Identifier Available", TEST_single_subscription_identifier_available)
			|| !CU_add_test(test_suite, "Single Shared Subscription Available", TEST_single_shared_subscription_available)
			|| !CU_add_test(test_suite, "Single Message Expiry Interval", TEST_single_message_expiry_interval)
			|| !CU_add_test(test_suite, "Single Session Expiry Interval", TEST_single_session_expiry_interval)
			|| !CU_add_test(test_suite, "Single Will Delay Interval", TEST_single_will_delay_interval)
			|| !CU_add_test(test_suite, "Single Maximum Packet Size", TEST_single_maximum_packet_size)
			|| !CU_add_test(test_suite, "Single Server Keep Alive", TEST_single_server_keep_alive)
			|| !CU_add_test(test_suite, "Single Receive Maximum", TEST_single_receive_maximum)
			|| !CU_add_test(test_suite, "Single Topic Alias Maximum", TEST_single_topic_alias_maximum)
			|| !CU_add_test(test_suite, "Single Topic Alias", TEST_single_topic_alias)
			|| !CU_add_test(test_suite, "Single Content Type", TEST_single_content_type)
			|| !CU_add_test(test_suite, "Single Response Topic", TEST_single_response_topic)
			|| !CU_add_test(test_suite, "Single Assigned Client Identifier", TEST_single_assigned_client_identifier)
			|| !CU_add_test(test_suite, "Single Authentication Method", TEST_single_authentication_method)
			|| !CU_add_test(test_suite, "Single Response Information", TEST_single_response_information)
			|| !CU_add_test(test_suite, "Single Server Reference", TEST_single_server_reference)
			|| !CU_add_test(test_suite, "Single Reason String", TEST_single_reason_string)
			|| !CU_add_test(test_suite, "Single Correlation Data", TEST_single_correlation_data)
			|| !CU_add_test(test_suite, "Single Authentication Data", TEST_single_authentication_data)
			|| !CU_add_test(test_suite, "Single User Property", TEST_single_user_property)
			|| !CU_add_test(test_suite, "Single Subscription Identifier", TEST_single_subscription_identifier)
			|| !CU_add_test(test_suite, "Duplicate Payload Format Indicator", TEST_duplicate_payload_format_indicator)
			|| !CU_add_test(test_suite, "Duplicate Request Problem Information", TEST_duplicate_request_problem_information)
			|| !CU_add_test(test_suite, "Duplicate Request Response Information", TEST_duplicate_request_response_information)
			|| !CU_add_test(test_suite, "Duplicate Maximum QoS", TEST_duplicate_maximum_qos)
			|| !CU_add_test(test_suite, "Duplicate Retain Available", TEST_duplicate_retain_available)
			|| !CU_add_test(test_suite, "Duplicate Wildcard Subscription Available", TEST_duplicate_wildcard_subscription_available)
			|| !CU_add_test(test_suite, "Duplicate Subscription Identifier Available", TEST_duplicate_subscription_identifier_available)
			|| !CU_add_test(test_suite, "Duplicate Shared Subscription Available", TEST_duplicate_shared_subscription_available)
			|| !CU_add_test(test_suite, "Duplicate Message Expiry Interval", TEST_duplicate_message_expiry_interval)
			|| !CU_add_test(test_suite, "Duplicate Session Expiry Interval", TEST_duplicate_session_expiry_interval)
			|| !CU_add_test(test_suite, "Duplicate Will Delay Interval", TEST_duplicate_will_delay_interval)
			|| !CU_add_test(test_suite, "Duplicate Maximum Packet Size", TEST_duplicate_maximum_packet_size)
			|| !CU_add_test(test_suite, "Duplicate Server Keep Alive", TEST_duplicate_server_keep_alive)
			|| !CU_add_test(test_suite, "Duplicate Receive Maximum", TEST_duplicate_receive_maximum)
			|| !CU_add_test(test_suite, "Duplicate Topic Alias Maximum", TEST_duplicate_topic_alias_maximum)
			|| !CU_add_test(test_suite, "Duplicate Topic Alias", TEST_duplicate_topic_alias)
			|| !CU_add_test(test_suite, "Duplicate Content Type", TEST_duplicate_content_type)
			|| !CU_add_test(test_suite, "Duplicate Response Topic", TEST_duplicate_response_topic)
			|| !CU_add_test(test_suite, "Duplicate Assigned Client ID", TEST_duplicate_assigned_client_identifier)
			|| !CU_add_test(test_suite, "Duplicate Authentication Method", TEST_duplicate_authentication_method)
			|| !CU_add_test(test_suite, "Duplicate Response Information", TEST_duplicate_response_information)
			|| !CU_add_test(test_suite, "Duplicate Server Reference", TEST_duplicate_server_reference)
			|| !CU_add_test(test_suite, "Duplicate Reason String", TEST_duplicate_reason_string)
			|| !CU_add_test(test_suite, "Duplicate Correlation Data", TEST_duplicate_correlation_data)
			|| !CU_add_test(test_suite, "Duplicate Authentication Data", TEST_duplicate_authentication_data)
			|| !CU_add_test(test_suite, "Duplicate User Property", TEST_duplicate_user_property)
			|| !CU_add_test(test_suite, "Duplicate Subscription Identifier", TEST_duplicate_subscription_identifier)
			|| !CU_add_test(test_suite, "Bad Request Problem Information", TEST_bad_request_problem_information)
			|| !CU_add_test(test_suite, "Bad Request Response Information", TEST_bad_request_response_information)
			|| !CU_add_test(test_suite, "Bad Maximum QoS", TEST_bad_maximum_qos)
			|| !CU_add_test(test_suite, "Bad Retain Available", TEST_bad_retain_available)
			|| !CU_add_test(test_suite, "Bad Wildcard Subscription Available", TEST_bad_wildcard_sub_available)
			|| !CU_add_test(test_suite, "Bad Subscription Identifier Available", TEST_bad_subscription_id_available)
			|| !CU_add_test(test_suite, "Bad Shared Subscription Available", TEST_bad_shared_sub_available)
			|| !CU_add_test(test_suite, "Bad Maximum Packet Size", TEST_bad_maximum_packet_size)
			|| !CU_add_test(test_suite, "Bad Receive Maximum", TEST_bad_receive_maximum)
			|| !CU_add_test(test_suite, "Bad Topic Alias", TEST_bad_topic_alias)
			|| !CU_add_test(test_suite, "Bad Content Type", TEST_bad_content_type)
			|| !CU_add_test(test_suite, "Bad Subscription Identifier", TEST_bad_subscription_identifier)
			|| !CU_add_test(test_suite, "Packet CONNECT", TEST_packet_connect)
			|| !CU_add_test(test_suite, "Packet CONNACK", TEST_packet_connack)
			|| !CU_add_test(test_suite, "Packet PUBLISH", TEST_packet_publish)
			|| !CU_add_test(test_suite, "Packet PUBACK", TEST_packet_puback)
			|| !CU_add_test(test_suite, "Packet PUBREC", TEST_packet_pubrec)
			|| !CU_add_test(test_suite, "Packet PUBREL", TEST_packet_pubrel)
			|| !CU_add_test(test_suite, "Packet PUBCOMP", TEST_packet_pubcomp)
			|| !CU_add_test(test_suite, "Packet SUBSCRIBE", TEST_packet_subscribe)
			|| !CU_add_test(test_suite, "Packet SUBACK", TEST_packet_suback)
			|| !CU_add_test(test_suite, "Packet UNSUBSCRIBE", TEST_packet_unsubscribe)
			|| !CU_add_test(test_suite, "Packet UNSUBACK", TEST_packet_unsuback)
			|| !CU_add_test(test_suite, "Packet DISCONNECT", TEST_packet_disconnect)
			|| !CU_add_test(test_suite, "Packet AUTH", TEST_packet_auth)
			){

		printf("Error adding Property read CUnit tests.\n");
		return 1;
	}

	return 0;
}
