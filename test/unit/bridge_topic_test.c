#include "config.h"
#include <stdio.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#define WITH_BRIDGE
#define WITH_BROKER

#include "mosquitto_broker_internal.h"
#include "property_mosq.h"
#include "packet_mosq.h"

static void map_valid_helper(const char *topic, const char *local_prefix, const char *remote_prefix, const char *incoming, const char *expected)
{
	struct mosquitto mosq;
	struct mosquitto__bridge bridge;
	char *map_topic;
	int rc;

	memset(&mosq, 0, sizeof(struct mosquitto));
	memset(&bridge, 0, sizeof(struct mosquitto__bridge));

	mosq.bridge = &bridge;

	rc = bridge__add_topic(&bridge, topic, bd_in, 0, local_prefix, remote_prefix);
	CU_ASSERT_EQUAL(rc, 0);

	map_topic = strdup(incoming);
	rc = bridge__remap_topic_in(&mosq, &map_topic);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_PTR_NOT_NULL(map_topic);
	if(map_topic){
		CU_ASSERT_STRING_EQUAL(map_topic, expected);
		free(map_topic);
	}
}

static void map_invalid_helper(const char *topic, const char *local_prefix, const char *remote_prefix)
{
	struct mosquitto mosq;
	struct mosquitto__bridge bridge;
	int rc;

	memset(&mosq, 0, sizeof(struct mosquitto));
	memset(&bridge, 0, sizeof(struct mosquitto__bridge));

	mosq.bridge = &bridge;

	rc = bridge__add_topic(&bridge, topic, bd_in, 0, local_prefix, remote_prefix);
	CU_ASSERT_NOT_EQUAL(rc, 0);
}


static void TEST_remap_valid(void)
{
	/* Examples from man page */
	map_valid_helper("pattern", "L/", "R/", "R/pattern", "L/pattern");
	map_valid_helper("pattern", "L/", NULL, "pattern", "L/pattern");
	map_valid_helper("pattern", NULL, "R/", "R/pattern", "pattern");
	map_valid_helper("pattern", NULL, NULL, "pattern", "pattern");
	map_valid_helper(NULL, "local", "remote", "remote", "local");
}

static void TEST_remap_invalid(void)
{
	/* Examples from man page */
	map_invalid_helper(NULL, "L/", NULL);
	map_invalid_helper(NULL, NULL, "R/");
	map_invalid_helper(NULL, NULL, NULL);
}


/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */

int init_bridge_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("Bridge remap", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit Bridge remap test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Remap valid", TEST_remap_valid)
			|| !CU_add_test(test_suite, "Remap invalid", TEST_remap_invalid)
			){

		printf("Error adding Bridge remap CUnit tests.\n");
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	unsigned int fails;

	UNUSED(argc);
	UNUSED(argv);

    if(CU_initialize_registry() != CUE_SUCCESS){
        printf("Error initializing CUnit registry.\n");
        return 1;
    }

    if(0
			|| init_bridge_tests()
			){

        CU_cleanup_registry();
        return 1;
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
	fails = CU_get_number_of_failures();
    CU_cleanup_registry();

    return (int)fails;
}

