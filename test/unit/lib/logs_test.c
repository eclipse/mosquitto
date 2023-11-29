/* Tests of log filtering */

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include <util_mosq.h>
#include <logging_mosq.h>

unsigned int last_log_level;

static void on_log(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	last_log_level = (unsigned int)level;
	UNUSED(mosq);
	UNUSED(obj);
	UNUSED(str);
}

static bool log_on_level(struct mosquitto *mosq, unsigned int level)
{
	last_log_level = MOSQ_LOG_ALL;
	log__printf(mosq, level, "msg");
	return last_log_level == level;
}

static void TEST_logs(void)
{
	struct mosquitto *mosq;

	mosquitto_lib_init();
	mosq = mosquitto_new("log check", true, NULL);
	CU_ASSERT(mosq != NULL);
	mosquitto_log_callback_set(mosq, on_log);

	/* default (log all) */
	CU_ASSERT(log_on_level(mosq, MOSQ_LOG_INFO));
	CU_ASSERT(log_on_level(mosq, MOSQ_LOG_ERR));
	CU_ASSERT(log_on_level(mosq, MOSQ_LOG_SUBSCRIBE));

	/* warning and above */
	mosquitto_log_levels_set(mosq, MOSQ_LOG_WARNING_AND_ABOVE);
	CU_ASSERT(!log_on_level(mosq, MOSQ_LOG_INFO));
	CU_ASSERT(log_on_level(mosq, MOSQ_LOG_WARNING));
	CU_ASSERT(!log_on_level(mosq, MOSQ_LOG_DEBUG));
	CU_ASSERT(log_on_level(mosq, MOSQ_LOG_ERR));
	CU_ASSERT(!log_on_level(mosq, MOSQ_LOG_SUBSCRIBE));

	/* errors and subscribe */
	mosquitto_log_levels_set(mosq, MOSQ_LOG_ERR | MOSQ_LOG_SUBSCRIBE);
	CU_ASSERT(!log_on_level(mosq, MOSQ_LOG_DEBUG));
	CU_ASSERT(!log_on_level(mosq, MOSQ_LOG_WARNING));
	CU_ASSERT(log_on_level(mosq, MOSQ_LOG_ERR));
	CU_ASSERT(log_on_level(mosq, MOSQ_LOG_SUBSCRIBE));

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
}

/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */


int main(int argc, char *argv[])
{
	CU_pSuite test_suite = NULL;
	unsigned int fails;

	UNUSED(argc);
	UNUSED(argv);

	if(CU_initialize_registry() != CUE_SUCCESS){
		printf("Error initializing CUnit registry.\n");
		return 1;
	}

	test_suite = CU_add_suite("Logs", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit Logs test suite.\n");
		CU_cleanup_registry();
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Logs", TEST_logs)
			){

		printf("Error adding Logs CUnit tests.\n");
		CU_cleanup_registry();
		return 1;
	}

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	fails = CU_get_number_of_failures();
	CU_cleanup_registry();

	return (int)fails;
}
