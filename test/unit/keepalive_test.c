/* Tests for keepalive add/remove/update. */

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#define WITH_BROKER
#define WITH_PERSISTENCE

#include "keepalive.c"

#include "mosquitto_internal.h"
#include "mosquitto_broker_internal.h"

struct mosquitto_db db;

void do_disconnect(struct mosquitto *context, int reason)
{
	UNUSED(reason);

	keepalive__remove(context);
}


static void TEST_single_client(void)
{
	struct mosquitto context;
	int rc;

	memset(&db, 0, sizeof(db));
	memset(&context, 0, sizeof(context));

	db.now_s = 1000;
	db.config = calloc(1, sizeof(struct mosquitto__config));
	CU_ASSERT_PTR_NOT_NULL(db.config);
	if(db.config == NULL){
		return;
	}
	db.config->max_keepalive = 2000;

	context.id = strdup("clientid1");
	context.keepalive = 60;
	context.last_msg_in = db.now_s;

	rc = keepalive__init();
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS){
		return;
	}
	CU_ASSERT_EQUAL(keepalive_list_max, 3001);
	CU_ASSERT_PTR_NOT_NULL(keepalive_list);

	rc = keepalive__add(&context);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(keepalive_list[context.last_msg_in + context.keepalive*3/2]);

	keepalive__check();
	CU_ASSERT_PTR_NOT_NULL(keepalive_list[context.last_msg_in + context.keepalive*3/2]);

	/* Should be just before the client expires */
	db.now_s = 1090;
	keepalive__check();
	CU_ASSERT_PTR_NOT_NULL(keepalive_list[context.last_msg_in + context.keepalive*3/2]);

	/* Should be just as the client expires */
	db.now_s = 1091;
	keepalive__check();
	CU_ASSERT_PTR_NULL(keepalive_list[context.last_msg_in + context.keepalive*3/2]);

	keepalive__cleanup();

	free(db.config);
	free(context.id);
}

static void TEST_single_client_update(void)
{
	struct mosquitto context;
	int rc;

	memset(&db, 0, sizeof(db));
	memset(&context, 0, sizeof(context));

	db.now_s = 1000;
	db.config = calloc(1, sizeof(struct mosquitto__config));
	CU_ASSERT_PTR_NOT_NULL(db.config);
	if(db.config == NULL){
		return;
	}
	db.config->max_keepalive = 2000;

	context.id = strdup("clientid1");
	context.keepalive = 60;
	context.last_msg_in = db.now_s;

	rc = keepalive__init();
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS){
		return;
	}
	CU_ASSERT_EQUAL(keepalive_list_max, 3001);
	CU_ASSERT_PTR_NOT_NULL(keepalive_list);

	rc = keepalive__add(&context);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(keepalive_list[context.last_msg_in + context.keepalive*3/2]);

	keepalive__check();
	CU_ASSERT_PTR_NOT_NULL(keepalive_list[context.last_msg_in + context.keepalive*3/2]);

	db.now_s = 1090;
	keepalive__check();
	CU_ASSERT_PTR_NOT_NULL(keepalive_list[context.last_msg_in + context.keepalive*3/2]);

	/* Receive a new message and do an update */
	keepalive__update(&context);
	CU_ASSERT_PTR_NOT_NULL(keepalive_list[context.last_msg_in + context.keepalive*3/2]);

	keepalive__cleanup();

	free(db.config);
	free(context.id);
}

static void TEST_over_max_keepalive(void)
{
	struct mosquitto context;
	int rc;

	memset(&db, 0, sizeof(db));
	memset(&context, 0, sizeof(context));

	db.now_s = 1000;
	db.config = calloc(1, sizeof(struct mosquitto__config));
	CU_ASSERT_PTR_NOT_NULL(db.config);
	if(db.config == NULL){
		return;
	}
	db.config->max_keepalive = 2000;

	context.id = strdup("clientid1");
	/* Client keepalive too big. This won't be allowed at connection time, but
	 * may occur if max_keepalive is lowered and the config reloaded only. The
	 * client will end up being expired most likely. */
	context.keepalive = 2001;
	context.last_msg_in = db.now_s;

	rc = keepalive__init();
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS){
		return;
	}
	CU_ASSERT_EQUAL(keepalive_list_max, 3001);
	CU_ASSERT_PTR_NOT_NULL(keepalive_list);

	rc = keepalive__add(&context);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(keepalive_list[(context.last_msg_in + context.keepalive*3/2) % keepalive_list_max]);

	keepalive__cleanup();

	free(db.config);
	free(context.id);
}

static void TEST_100k_random_clients(void)
{
	struct mosquitto *contexts;
	int rc;
	const int client_count = 100000;
	int client_total, cur_count;

	/* This is a very crude test, adding 100k clients with random keepalive and
	 * random last message in. */

	srand((unsigned int)time(NULL));

	memset(&db, 0, sizeof(db));

	contexts = calloc(client_count, sizeof(struct mosquitto));
	db.now_s = 1000;
	db.config = calloc(1, sizeof(struct mosquitto__config));
	if(db.config == NULL){
		return;
	}
	CU_ASSERT_PTR_NOT_NULL(db.config);
	db.config->max_keepalive = 0;

	for(int i=0; i<client_count; i++){
		contexts[i].id = strdup("clientid");
		contexts[i].keepalive = (uint16_t)rand() % UINT16_MAX;
		contexts[i].last_msg_in = rand() % 60000;
	}

	rc = keepalive__init();
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	if(rc != MOSQ_ERR_SUCCESS){
		return;
	}
	CU_ASSERT_EQUAL(keepalive_list_max, 98303);
	CU_ASSERT_PTR_NOT_NULL(keepalive_list);

	for(int i=0; i<client_count; i++){
		rc = keepalive__add(&contexts[i]);
		CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	}

	/* Count clients */
	client_total = 0;
	for(int i=0; i<keepalive_list_max; i++){
		struct mosquitto *ctx;

		DL_COUNT2(keepalive_list[i], ctx, cur_count, keepalive_next);
		client_total += cur_count;
	}
	/* FIXME
	CU_ASSERT_EQUAL(client_total, client_count);
	*/

	for(db.now_s = 1000; db.now_s < 100000; db.now_s++){
		keepalive__check();
	}
	keepalive__cleanup();

	for(int i=0; i<client_count; i++){
		free(contexts[i].id);
	}
	free(contexts);
	free(db.config);
}

/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */

int init_keepalive_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("Keepalive", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit keepalive test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "single client", TEST_single_client)
			|| !CU_add_test(test_suite, "single client update", TEST_single_client_update)
			|| !CU_add_test(test_suite, "keepalive > max_keepalive", TEST_over_max_keepalive)
			|| !CU_add_test(test_suite, "100k random clients", TEST_100k_random_clients)
			){

		printf("Error adding keepalive CUnit tests.\n");
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
			|| init_keepalive_tests()
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
