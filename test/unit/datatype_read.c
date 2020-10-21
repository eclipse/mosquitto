#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "packet_mosq.h"

static void byte_read_helper(
		uint8_t *payload,
		uint32_t remaining_length,
		int rc_expected,
		uint8_t value_expected)
{
	struct mosquitto__packet packet;
	uint8_t value = 0;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = packet__read_byte(&packet, &value);
	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(value, value_expected);
}


static void uint16_read_helper(
		uint8_t *payload,
		uint32_t remaining_length,
		int rc_expected,
		uint16_t value_expected)
{
	struct mosquitto__packet packet;
	uint16_t value = 0;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = packet__read_uint16(&packet, &value);
	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(value, value_expected);
}


static void uint32_read_helper(
		uint8_t *payload,
		uint32_t remaining_length,
		int rc_expected,
		uint32_t value_expected)
{
	struct mosquitto__packet packet;
	uint32_t value = 0;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = packet__read_uint32(&packet, &value);
	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(value, value_expected);
}


static void varint_read_helper(
		uint8_t *payload,
		uint32_t remaining_length,
		int rc_expected,
		uint32_t value_expected,
		uint8_t bytes_expected)
{
	struct mosquitto__packet packet;
	uint32_t value = UINT32_MAX;
	uint8_t bytes = UINT8_MAX;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = packet__read_varint(&packet, &value, &bytes);
	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(value, value_expected);
	CU_ASSERT_EQUAL(bytes, bytes_expected);
}


static void binary_read_helper(
		uint8_t *payload,
		uint32_t remaining_length,
		int rc_expected,
		const uint8_t *value_expected,
		int length_expected)
{
	struct mosquitto__packet packet;
	uint8_t *value = NULL;
	uint16_t length = UINT16_MAX;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = packet__read_binary(&packet, (uint8_t **)&value, &length);
	CU_ASSERT_EQUAL(rc, rc_expected);
	if(value_expected){
		/* FIXME - this should be a memcmp */
		CU_ASSERT_NSTRING_EQUAL(value, value_expected, length_expected);
	}else{
		CU_ASSERT_EQUAL(value, NULL);
	}
	CU_ASSERT_EQUAL(length, length_expected);
	free(value);
}


static void string_read_helper(
		uint8_t *payload,
		uint32_t remaining_length,
		int rc_expected,
		const uint8_t *value_expected,
		uint16_t length_expected)
{
	struct mosquitto__packet packet;
	uint8_t *value = NULL;
	uint16_t length = UINT16_MAX;
	int rc;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = packet__read_string(&packet, (char **)&value, &length);
	CU_ASSERT_EQUAL(rc, rc_expected);
	if(value_expected){
		if(value){
			CU_ASSERT_NSTRING_EQUAL(value, value_expected, length_expected);
		}
	}else{
		CU_ASSERT_PTR_NULL(value);
	}
	CU_ASSERT_EQUAL(length, length_expected);
	free(value);
}


static void bytes_read_helper(
		uint8_t *payload,
		uint32_t remaining_length,
		int rc_expected,
		const uint8_t *value_expected,
		int count)
{
	struct mosquitto__packet packet;
	uint8_t value[count];
	int rc;
	int i;

	memset(&packet, 0, sizeof(struct mosquitto__packet));
	packet.payload = payload;
	packet.remaining_length = remaining_length;
	rc = packet__read_bytes(&packet, value, (uint32_t)count);
	CU_ASSERT_EQUAL(rc, rc_expected);
	if(rc == MOSQ_ERR_SUCCESS){
		CU_ASSERT_EQUAL(packet.pos, count);
	}
	if(value_expected){
		for(i=0; i<count; i++){
			CU_ASSERT_EQUAL(value[i], value_expected[i]);
		}
	}
}


/* ========================================================================
 * BYTE INTEGER TESTS
 * ======================================================================== */

/* This tests reading a Byte from an incoming packet.
 *
 * It tests:
 *  * Empty packets
 */
static void TEST_byte_read_empty(void)
{
	/* Empty packet */
	byte_read_helper(NULL, 0, MOSQ_ERR_PROTOCOL, 0);
}


/* This tests reading a Byte from an incoming packet.
 *
 * It tests:
 *  * Success at boundaries
 */
static void TEST_byte_read_success(void)
{
	uint8_t payload[20];

	/* 0 value */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00;
	byte_read_helper(payload, 1, MOSQ_ERR_SUCCESS, 0x00);

	/* Middle */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x1F;
	byte_read_helper(payload, 1, MOSQ_ERR_SUCCESS, 0x1F);

	/* 255 value */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0xFF;
	byte_read_helper(payload, 1, MOSQ_ERR_SUCCESS, 0xFF);

}


/* ========================================================================
 * TWO BYTE INTEGER TESTS
 * ======================================================================== */

/* This tests reading a Two Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Empty packets
 */
static void TEST_uint16_read_empty(void)
{
	/* Empty packet */
	uint16_read_helper(NULL, 0, MOSQ_ERR_PROTOCOL, 0);
}


/* This tests reading a Two Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Truncated packets
 */
static void TEST_uint16_read_truncated(void)
{
	uint8_t payload[20];

	/* 1 byte packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x38;
	uint16_read_helper(payload, 1, MOSQ_ERR_PROTOCOL, 0);
}


/* This tests reading a Two Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Success at boundaries
 *  * Endianness
 */
static void TEST_uint16_read_success(void)
{
	uint8_t payload[20];

	/* 0 value */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00;
	payload[1] = 0x00;
	uint16_read_helper(payload, 2, MOSQ_ERR_SUCCESS, 0x0000);

	/* Endian check */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x38;
	payload[1] = 0xF3;
	uint16_read_helper(payload, 2, MOSQ_ERR_SUCCESS, 0x38F3);

	/* 65,535 value */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0xFF;
	payload[1] = 0xFF;
	uint16_read_helper(payload, 2, MOSQ_ERR_SUCCESS, 0xFFFF);

}


/* ========================================================================
 * FOUR BYTE INTEGER TESTS
 * ======================================================================== */

/* This tests reading a Four Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Empty packets
 */
static void TEST_uint32_read_empty(void)
{
	/* Empty packet */
	uint32_read_helper(NULL, 0, MOSQ_ERR_PROTOCOL, 0);
}


/* This tests reading a Four Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Truncated packets
 */
static void TEST_uint32_read_truncated(void)
{
	uint8_t payload[20];

	/* 1 byte packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x38;
	uint32_read_helper(payload, 1, MOSQ_ERR_PROTOCOL, 0);

	/* 2 byte packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x38;
	payload[1] = 0x38;
	uint32_read_helper(payload, 2, MOSQ_ERR_PROTOCOL, 0);

	/* 3 byte packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x38;
	payload[1] = 0x38;
	payload[2] = 0x38;
	uint32_read_helper(payload, 3, MOSQ_ERR_PROTOCOL, 0);
}


/* This tests reading a Four Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Success at boundaries
 *  * Endianness
 */
static void TEST_uint32_read_success(void)
{
	uint8_t payload[20];

	/* 0 value */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00;
	payload[1] = 0x00;
	payload[2] = 0x00;
	payload[3] = 0x00;
	uint32_read_helper(payload, 4, MOSQ_ERR_SUCCESS, 0x00000000);

	/* Endian check */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x12;
	payload[1] = 0x34;
	payload[2] = 0x56;
	payload[3] = 0x78;
	uint32_read_helper(payload, 4, MOSQ_ERR_SUCCESS, 0x12345678);

	/* Biggest value */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0xFF;
	payload[1] = 0xFF;
	payload[2] = 0xFF;
	payload[3] = 0xFF;
	uint32_read_helper(payload, 4, MOSQ_ERR_SUCCESS, 0xFFFFFFFF);

}


/* ========================================================================
 * VARIABLE BYTE INTEGER TESTS
 * ======================================================================== */

/* This tests reading a Variable Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Empty packet
 */
static void TEST_varint_read_empty(void)
{
	/* Empty packet */
	varint_read_helper(NULL, 0, MOSQ_ERR_PROTOCOL, UINT32_MAX, UINT8_MAX);
}


/* This tests reading a Variable Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Truncated packets (varint encoding is longer than data)
 */
static void TEST_varint_read_truncated(void)
{
	uint8_t payload[20];

	/* Varint bigger than packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x80;
	varint_read_helper(payload, 1, MOSQ_ERR_PROTOCOL, UINT32_MAX, UINT8_MAX);

	/* Varint bigger than packet */
	memset(payload, 1, sizeof(payload));
	payload[0] = 0x80;
	payload[1] = 0x80;
	varint_read_helper(payload, 2, MOSQ_ERR_PROTOCOL, UINT32_MAX, UINT8_MAX);

	/* Varint bigger than packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x80;
	payload[1] = 0x80;
	payload[2] = 0x80;
	varint_read_helper(payload, 3, MOSQ_ERR_PROTOCOL, UINT32_MAX, UINT8_MAX);

	/* Varint bigger than packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x80;
	payload[1] = 0x80;
	payload[2] = 0x80;
	payload[3] = 0x80;
	varint_read_helper(payload, 4, MOSQ_ERR_PROTOCOL, UINT32_MAX, UINT8_MAX);
}


/* This tests reading a Variable Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Correct values on boundaries of 1, 2, 3, 4 byte encodings
 */
static void TEST_varint_read_boundaries(void)
{
	uint8_t payload[20];

	/* Value = 0 */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00;
	varint_read_helper(payload, 1, MOSQ_ERR_SUCCESS, 0, 1);

	/* Value = 127 (just beneath the crossover to two bytes */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x7F;
	varint_read_helper(payload, 1, MOSQ_ERR_SUCCESS, 127, 1);

	/* Value = 128 (just after the crossover to two bytes */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x80;
	payload[1] = 0x01;
	varint_read_helper(payload, 2, MOSQ_ERR_SUCCESS, 128, 2);

	/* Value = 16383 (just before the crossover to three bytes */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0xFF;
	payload[1] = 0x7F;
	varint_read_helper(payload, 2, MOSQ_ERR_SUCCESS, 16383, 2);

	/* Value = 16384 (just after the crossover to three bytes */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x80;
	payload[1] = 0x80;
	payload[2] = 0x01;
	varint_read_helper(payload, 3, MOSQ_ERR_SUCCESS, 16384, 3);

	/* Value = 2,097,151 (just before the crossover to four bytes */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0xFF;
	payload[1] = 0xFF;
	payload[2] = 0x7F;
	varint_read_helper(payload, 3, MOSQ_ERR_SUCCESS, 2097151, 3);

	/* Value = 2,097,152 (just after the crossover to four bytes */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x80;
	payload[1] = 0x80;
	payload[2] = 0x80;
	payload[3] = 0x01;
	varint_read_helper(payload, 4, MOSQ_ERR_SUCCESS, 2097152, 4);

	/* Value = 268,435,455 (highest value allowed) */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0xFF;
	payload[1] = 0xFF;
	payload[2] = 0xFF;
	payload[3] = 0x7F;
	varint_read_helper(payload, 4, MOSQ_ERR_SUCCESS, 268435455, 4);
}

/* This tests reading a Variable Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Too long encoding (5 bytes)
 */
static void TEST_varint_read_5_bytes(void)
{
	uint8_t payload[20];

	/* Value = 268,435,456 (one higher than highest value allowed) */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x80;
	payload[1] = 0x80;
	payload[2] = 0x80;
	payload[3] = 0x80;
	payload[4] = 0x01;
	varint_read_helper(payload, 5, MOSQ_ERR_PROTOCOL, UINT32_MAX, UINT8_MAX);
}


/* This tests reading a Variable Byte Integer from an incoming packet.
 *
 * It tests:
 *  * Overlong encodings (e.g. 2 bytes to encode "1")
 */
static void TEST_varint_read_overlong_encoding(void)
{
	uint8_t payload[20];

	/* Overlong encoding of 0 (1 byte value encoded as 2 bytes) */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x80;
	payload[1] = 0x00;
	varint_read_helper(payload, 2, MOSQ_ERR_PROTOCOL, UINT32_MAX, UINT8_MAX);

	/* Overlong encoding of 127 (1 byte value encoded as 2 bytes) */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0xFF;
	payload[1] = 0x00;
	varint_read_helper(payload, 2, MOSQ_ERR_PROTOCOL, UINT32_MAX, UINT8_MAX);

	/* Overlong encoding of 128 (2 byte value encoded as 3 bytes) */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x80;
	payload[1] = 0x81;
	payload[2] = 0x00;
	varint_read_helper(payload, 3, MOSQ_ERR_PROTOCOL, UINT32_MAX, UINT8_MAX);

	/* Overlong encoding of 16,383 (2 byte value encoded as 3 bytes) */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0xFF;
	payload[1] = 0xFF;
	payload[2] = 0x00;
	varint_read_helper(payload, 3, MOSQ_ERR_PROTOCOL, UINT32_MAX, UINT8_MAX);

	/* Overlong encoding of 16,384 (3 byte value encoded as 4 bytes) */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x80;
	payload[1] = 0x80;
	payload[2] = 0x81;
	payload[3] = 0x00;
	varint_read_helper(payload, 4, MOSQ_ERR_PROTOCOL, UINT32_MAX, UINT8_MAX);

	/* Overlong encoding of 2,097,151 (3 byte value encoded as 4 bytes) */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0xFF;
	payload[1] = 0xFF;
	payload[2] = 0xFF;
	payload[3] = 0x00;
	varint_read_helper(payload, 4, MOSQ_ERR_PROTOCOL, UINT32_MAX, UINT8_MAX);
}


/* ========================================================================
 * UTF-8 STRING TESTS
 * ======================================================================== */

/* This tests reading a UTF-8 Encoded String from an incoming packet.
 *
 * It tests:
 *  * Empty packet
 */
static void TEST_string_read_empty(void)
{
	string_read_helper(NULL, 0, MOSQ_ERR_PROTOCOL, NULL, UINT16_MAX);
}

/* This tests reading a UTF-8 Encoded String from an incoming packet.
 *
 * It tests:
 *  * Truncated packets
 */
static void TEST_string_read_truncated(void)
{
	uint8_t payload[20];

	/* 1 byte packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x02;
	string_read_helper(payload, 1, MOSQ_ERR_PROTOCOL, NULL, UINT16_MAX);

	/* 2 byte packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x02;
	payload[1] = 0x02;
	string_read_helper(payload, 2, MOSQ_ERR_PROTOCOL, NULL, UINT16_MAX);

	/* 3 byte packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00;
	payload[1] = 0x02;
	payload[2] = 'a';
	string_read_helper(payload, 3, MOSQ_ERR_PROTOCOL, NULL, UINT16_MAX);

	/* 3 byte packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00;
	payload[1] = 0x03;
	payload[2] = 'a';
	payload[3] = 'b';
	string_read_helper(payload, 4, MOSQ_ERR_PROTOCOL, NULL, UINT16_MAX);
}


/* This tests reading a UTF-8 Encoded String from an incoming packet.
 *
 * It tests:
 *  * Empty string
 */
static void TEST_string_read_empty_string(void)
{
	uint8_t payload[20];

	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00;
	payload[1] = 0x00;
	string_read_helper(payload, 2, MOSQ_ERR_SUCCESS, (const uint8_t *)"", 0);
}

/* This tests reading a UTF-8 Encoded String from an incoming packet.
 *
 * It tests:
 *  * Valid string
 */
static void TEST_string_read_valid_string(void)
{
	uint8_t payload[20];

	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00;
	payload[1] = 0x0b;
	payload[2] = 't';
	payload[3] = 'e';
	payload[4] = 's';
	payload[5] = 't';
	payload[6] = ' ';
	payload[7] = 's';
	payload[8] = 't';
	payload[9] = 'r';
	payload[10] = 'i';
	payload[11] = 'n';
	payload[12] = 'g';
	string_read_helper(payload, 13, MOSQ_ERR_SUCCESS, (const uint8_t *)"test string", 11);
}


/* This tests reading a UTF-8 Encoded String from an incoming packet.
 *
 * It tests:
 *  * Malformed UTF-8 (note, comprehensive UTF-8 tests are elsewhere)
 */
static void TEST_string_read_malformed_string(void)
{
	uint8_t payload[20];

	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00;
	payload[1] = 0x07;
	payload[2] = 't';
	payload[3] = 'e';
	payload[4] = 's';
	payload[5] = 't';
	payload[6] = 0xED; /* U+D800 - single UTF-16 surrogate */
	payload[7] = 0xA0;
	payload[8] = 0x80;
	string_read_helper(payload, 9, MOSQ_ERR_MALFORMED_UTF8, NULL, 0);
}


/* This tests reading a UTF-8 Encoded String from an incoming packet.
 *
 * It tests:
 *  * MQTT-1.5.4-3 - Is 0xEF 0xBB 0xBF treated correctly.
 */
static void TEST_string_read_mqtt_1_5_4_3(void)
{
	uint8_t payload[20];

	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00;
	payload[1] = 0x0b;
	payload[2] = 't';
	payload[3] = 'e';
	payload[4] = 's';
	payload[5] = 't';
	payload[6] = 0xEF; /* U+FEFF - zero with no-break space */
	payload[7] = 0xBB;
	payload[8] = 0xBF;
	payload[9] = 't';
	payload[10] = 'e';
	payload[11] = 's';
	payload[12] = 't';
	string_read_helper(payload, 13, MOSQ_ERR_SUCCESS, &payload[2], 11);
}


/* ========================================================================
 * BINARY DATA TESTS
 * ======================================================================== */

/* This tests reading Binary Data from an incoming packet.
 *
 * It tests:
 *  * Empty packet
 */
static void TEST_binary_data_read_empty(void)
{
	binary_read_helper(NULL, 0, MOSQ_ERR_PROTOCOL, NULL, UINT16_MAX);
}


/* This tests reading Binary Data from an incoming packet.
 *
 * It tests:
 *  * Truncated packets
 */
static void TEST_binary_data_read_truncated(void)
{
	uint8_t payload[20];

	/* 1 byte packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x02;
	binary_read_helper(payload, 1, MOSQ_ERR_PROTOCOL, NULL, UINT16_MAX);

	/* 2 byte packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x02;
	payload[1] = 0x02;
	binary_read_helper(payload, 2, MOSQ_ERR_PROTOCOL, NULL, UINT16_MAX);

	/* 3 byte packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00;
	payload[1] = 0x02;
	payload[2] = 'a';
	binary_read_helper(payload, 3, MOSQ_ERR_PROTOCOL, NULL, UINT16_MAX);

	/* 3 byte packet */
	memset(payload, 0, sizeof(payload));
	payload[0] = 0x00;
	payload[1] = 0x03;
	payload[2] = 'a';
	payload[3] = 'b';
	binary_read_helper(payload, 4, MOSQ_ERR_PROTOCOL, NULL, UINT16_MAX);
}


/* ========================================================================
 * MULTIPLE BYTE TESTS
 * ======================================================================== */

/* This tests reading multiple bytes (payload) from an incoming packet.
 *
 * It tests:
 *  * Empty packets
 */
static void TEST_bytes_read_empty(void)
{
	/* Empty packet */
	bytes_read_helper(NULL, 0, MOSQ_ERR_SUCCESS, NULL, 0);
}

/* This tests reading multiple bytes (payload) from an incoming packet.
 *
 * It tests:
 *  * Truncated packets
 */
static void TEST_bytes_read_truncated(void)
{
	bytes_read_helper(NULL, 0, MOSQ_ERR_PROTOCOL, NULL, 1);
}

/* This tests reading multiple bytes from an incoming packet.
 *
 * It tests:
 *  * Success
 */
static void TEST_bytes_read_success(void)
{
	uint8_t payload[20];
	uint8_t i;

	for(i=0; i<20; i++){
		payload[i] = (uint8_t)(i*2);
	}
	bytes_read_helper(payload, 20, MOSQ_ERR_SUCCESS, payload, 20);
}


/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */

int init_datatype_read_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("Datatype read", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Byte read (empty packet)", TEST_byte_read_empty)
			|| !CU_add_test(test_suite, "Byte read (success values)", TEST_byte_read_success)
			|| !CU_add_test(test_suite, "Two Byte Integer read (empty packet)", TEST_uint16_read_empty)
			|| !CU_add_test(test_suite, "Two Byte Integer read (truncated packet)", TEST_uint16_read_truncated)
			|| !CU_add_test(test_suite, "Two Byte Integer read (success values)", TEST_uint16_read_success)
			|| !CU_add_test(test_suite, "Four Byte Integer read (empty packet)", TEST_uint32_read_empty)
			|| !CU_add_test(test_suite, "Four Byte Integer read (truncated packet)", TEST_uint32_read_truncated)
			|| !CU_add_test(test_suite, "Four Byte Integer read (success values)", TEST_uint32_read_success)
			|| !CU_add_test(test_suite, "Variable Byte Integer read (empty packet)", TEST_varint_read_empty)
			|| !CU_add_test(test_suite, "Variable Byte Integer read (truncated packets)", TEST_varint_read_truncated)
			|| !CU_add_test(test_suite, "Variable Byte Integer read (encoding boundaries)", TEST_varint_read_boundaries)
			|| !CU_add_test(test_suite, "Variable Byte Integer read (five byte encoding)", TEST_varint_read_5_bytes)
			|| !CU_add_test(test_suite, "Variable Byte Integer read (overlong encodings)", TEST_varint_read_overlong_encoding)
			|| !CU_add_test(test_suite, "UTF-8 string read (empty packet)", TEST_string_read_empty)
			|| !CU_add_test(test_suite, "UTF-8 string read (truncated packet)", TEST_string_read_truncated)
			|| !CU_add_test(test_suite, "UTF-8 string read (empty string)", TEST_string_read_empty_string)
			|| !CU_add_test(test_suite, "UTF-8 string read (valid string)", TEST_string_read_valid_string)
			|| !CU_add_test(test_suite, "UTF-8 string read (malformed string)", TEST_string_read_malformed_string)
			|| !CU_add_test(test_suite, "UTF-8 string read (MQTT-1.5.4-3)", TEST_string_read_mqtt_1_5_4_3)
			|| !CU_add_test(test_suite, "Binary Data read (empty packet)", TEST_binary_data_read_empty)
			|| !CU_add_test(test_suite, "Binary Data read (truncated packet)", TEST_binary_data_read_truncated)
			|| !CU_add_test(test_suite, "Bytes read (empty packet)", TEST_bytes_read_empty)
			|| !CU_add_test(test_suite, "Bytes read (truncated packet)", TEST_bytes_read_truncated)
			|| !CU_add_test(test_suite, "Bytes read (success)", TEST_bytes_read_success)
			){

		printf("Error adding Datatype read CUnit tests.\n");
		return 1;
	}

	return 0;
}
