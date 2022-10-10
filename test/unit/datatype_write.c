#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include <arpa/inet.h>

#include "packet_mosq.h"

/* ========================================================================
 * BYTE TESTS
 * ======================================================================== */

/* This tests writing a Byte to an incoming packet.  */
static void TEST_byte_write(void)
{
	struct mosquitto__packet *packet;
	int i;
	int rc;

	rc = packet__alloc(&packet, 0, 260);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;

	packet->pos = 0; /* We don't need the command or RL parts, so make indexing easier below */
	for(i=0; i<256; i++){
		packet__write_byte(packet, (uint8_t)(255-i));
	}

	CU_ASSERT_EQUAL(packet->pos, 256);
	for(i=0; i<256; i++){
		CU_ASSERT_EQUAL(packet->payload[i], (uint8_t)(255-i));
	}
	free(packet);
}


/* ========================================================================
 * TWO BYTE INTEGER TESTS
 * ======================================================================== */

/* This tests writing a Two Byte Integer to an incoming packet.  */
static void TEST_uint16_write(void)
{
	uint16_t *payload16;
	struct mosquitto__packet *packet;
	int i;
	int rc;

	rc = packet__alloc(&packet, 0, 650);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS) return;

	packet->pos = 0; /* We don't need the command or RL parts, so make indexing easier below */
	for(i=0; i<325; i++){
		packet__write_uint16(packet, (uint16_t)(100*i));
	}

	CU_ASSERT_EQUAL(packet->pos, 650);
	payload16 = (uint16_t *)packet->payload;
	for(i=0; i<325; i++){
		CU_ASSERT_EQUAL(payload16[i], htons((uint16_t)(100*i)));
	}
	free(packet);
}


/* ========================================================================
 * FOUR BYTE INTEGER TESTS
 * ======================================================================== */

/* This tests writing a Four Byte Integer to an incoming packet.  */
static void TEST_uint32_write(void)
{
	uint32_t *payload32;
	struct mosquitto__packet *packet;
	int i;

	packet = calloc(1, sizeof(struct mosquitto__packet) + 42000);
	CU_ASSERT_PTR_NOT_NULL(packet);
	if(packet == NULL) return;

	packet->packet_length = 42000;

	for(i=0; i<10500; i++){
		packet__write_uint32(packet, (uint32_t)(1000*i));
	}

	CU_ASSERT_EQUAL(packet->pos, 42000);
	payload32 = (uint32_t *)packet->payload;
	for(i=0; i<10500; i++){
		CU_ASSERT_EQUAL(payload32[i], htonl((uint32_t)(1000*i)));
	}
	free(packet);
}


/* ========================================================================
 * UTF-8 STRING TESTS
 * ======================================================================== */

/* This tests writing a UTF-8 String to an incoming packet.  */
static void TEST_string_write(void)
{
	struct mosquitto__packet *packet;

	packet = calloc(1, sizeof(struct mosquitto__packet) + 100);
	CU_ASSERT_PTR_NOT_NULL(packet);
	if(packet == NULL) return;

	packet->packet_length = 100;

	packet__write_string(packet, "first test", strlen("first test"));
	packet__write_string(packet, "second test", strlen("second test"));

	CU_ASSERT_EQUAL(packet->pos, 2+10+2+11);
	CU_ASSERT_EQUAL(packet->payload[0], 0);
	CU_ASSERT_EQUAL(packet->payload[1], 10);
	CU_ASSERT_NSTRING_EQUAL(packet->payload+2, "first test", 10);
	CU_ASSERT_EQUAL(packet->payload[2+10+0], 0);
	CU_ASSERT_EQUAL(packet->payload[2+10+1], 11);
	CU_ASSERT_NSTRING_EQUAL(packet->payload+2+10+2, "second test", 11);

	free(packet);
}


/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */

int init_datatype_write_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("Datatype write", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Byte write", TEST_byte_write)
			|| !CU_add_test(test_suite, "Two Byte Integer write", TEST_uint16_write)
			|| !CU_add_test(test_suite, "Four Byte Integer write", TEST_uint32_write)
			|| !CU_add_test(test_suite, "UTF-8 String write", TEST_string_write)
			){

		printf("Error adding Datatype write CUnit tests.\n");
		return 1;
	}

	return 0;
}
