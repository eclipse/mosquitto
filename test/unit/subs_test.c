/* Tests for subscription adding/removing
 *
 * FIXME - these need to be aggressive about finding failures, at the moment
 * they are just confirming that good behaviour works. */

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#define WITH_BROKER
#define WITH_PERSISTENCE

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"

struct mosquitto_db db;

static void hier_quick_check(struct mosquitto__subhier **sub, struct mosquitto *context, const char *topic)
{
	if(sub != NULL){
		CU_ASSERT_EQUAL((*sub)->topic_len, strlen(topic));
		CU_ASSERT_PTR_NOT_NULL((*sub)->topic);
		if((*sub)->topic){
			CU_ASSERT_STRING_EQUAL((*sub)->topic, topic);
		}
		if(context){
			CU_ASSERT_PTR_NOT_NULL((*sub)->subs);
			if((*sub)->subs){
				CU_ASSERT_PTR_EQUAL((*sub)->subs->context, context);
				CU_ASSERT_PTR_NULL((*sub)->subs->next);
			}
		}else{
			CU_ASSERT_PTR_NULL((*sub)->subs);
		}
		(*sub) = (*sub)->children;
	}
}


static void TEST_sub_add_single(void)
{
	struct mosquitto__config config;
	struct mosquitto__listener listener;
	struct mosquitto context;
	struct mosquitto__subhier *sub;
	int rc;

	memset(&db, 0, sizeof(struct mosquitto_db));
	memset(&config, 0, sizeof(struct mosquitto__config));
	memset(&listener, 0, sizeof(struct mosquitto__listener));
	memset(&context, 0, sizeof(struct mosquitto));

	context.id = "client";

	db.config = &config;
	listener.port = 1883;
	config.listeners = &listener;
	config.listener_count = 1;

	db__open(&config);

	rc = sub__add(&context, "a/b/c/d/e", 0, 0, 0, &db.subs);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(db.subs);
	if(db.subs){
		sub = db.subs;
		
		hier_quick_check(&sub, NULL, "");
		hier_quick_check(&sub, NULL, "");
		hier_quick_check(&sub, NULL, "a");
		hier_quick_check(&sub, NULL, "b");
		hier_quick_check(&sub, NULL, "c");
		hier_quick_check(&sub, NULL, "d");
		hier_quick_check(&sub, &context, "e");
		CU_ASSERT_PTR_NULL(sub);
	}
	mosquitto__free(context.subs);
	db__close();
}


/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */


int main(int argc, char *argv[])
{
	CU_pSuite test_suite = NULL;
	unsigned int fails;

    if(CU_initialize_registry() != CUE_SUCCESS){
        printf("Error initializing CUnit registry.\n");
        return 1;
    }

	test_suite = CU_add_suite("Subs", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit Subs test suite.\n");
        CU_cleanup_registry();
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Sub add single", TEST_sub_add_single)
			){

		printf("Error adding Subs CUnit tests.\n");
		CU_cleanup_registry();
        return 1;
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
	fails = CU_get_number_of_failures();
    CU_cleanup_registry();

    return (int)fails;
}
