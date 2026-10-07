#include <stdio.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include <mosquitto_internal.h>
#include <util_mosq.h>


static void TEST_maximum_packet_size(void)
{
	struct mosquitto mosq;
	int rc;

	memset(&mosq, 0, sizeof(struct mosquitto));

	mosq.maximum_packet_size = 5;
	rc = mosquitto_publish(&mosq, NULL, "topic/oversize", strlen("payload"), "payload", 0, 0);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_OVERSIZE_PACKET);
}


/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */


int init_publish_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("Publish", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit Publish test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "v5: Maximum packet size", TEST_maximum_packet_size)
			){

		printf("Error adding Publish CUnit tests.\n");
		return 1;
	}

	return 0;
}
