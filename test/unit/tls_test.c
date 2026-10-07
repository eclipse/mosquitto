#include <stdio.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#define WITH_TLS

#include "tls_mosq.c"


//static int mosquitto__cmp_hostname_wildcard(char *certname, const char *hostname)


void hostname_cmp_helper(char *certname, const char *hostname, int expected)
{
	int rc = mosquitto__cmp_hostname_wildcard(certname, hostname);
	CU_ASSERT_EQUAL(rc, expected);
	if(rc != expected){
		printf("%d || %d\n", rc, expected);
	}
}


void TEST_tls_hostname_compare_null(void)
{
	hostname_cmp_helper(NULL, "localhost", 1);
	hostname_cmp_helper("localhost", NULL, 1);
	hostname_cmp_helper(NULL, NULL, 1);
}


void TEST_tls_hostname_compare_simple(void)
{
	hostname_cmp_helper("localhost", "localhost", 0);
	hostname_cmp_helper("localhost", "localhose", 15);
}


void TEST_tls_hostname_compare_bad_wildcard_format(void)
{
	hostname_cmp_helper("**localhost", "localhost", 1);
	hostname_cmp_helper("*,localhost", "localhost", 1);
	hostname_cmp_helper("*.", "localhost", 1);
}


void TEST_tls_hostname_compare_invalid_wildcard(void)
{
	hostname_cmp_helper("*.com", "example.com", 1);
	hostname_cmp_helper("*.com", "example.org", 1);
	hostname_cmp_helper("*.org", "example.org", 1);
}


void TEST_tls_hostname_compare_good_wildcard(void)
{
	hostname_cmp_helper("*.example.com", "test.example.com", 0);
	hostname_cmp_helper("*.example.com", "test.example.org", -12);
	hostname_cmp_helper("*.example.org", "test.example.org", 0);
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

	test_suite = CU_add_suite("Subs", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit TLS test suite.\n");
		CU_cleanup_registry();
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "TLS hostname compare null", TEST_tls_hostname_compare_null)
			|| !CU_add_test(test_suite, "TLS hostname compare simple", TEST_tls_hostname_compare_simple)
			|| !CU_add_test(test_suite, "TLS hostname compare bad wildcard format", TEST_tls_hostname_compare_bad_wildcard_format)
			|| !CU_add_test(test_suite, "TLS hostname compare invalid wildcard", TEST_tls_hostname_compare_invalid_wildcard)
			|| !CU_add_test(test_suite, "TLS hostname compare good wildcard", TEST_tls_hostname_compare_good_wildcard)
			){

		printf("Error adding TLS CUnit tests.\n");
		CU_cleanup_registry();
		return 1;
	}

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	fails = CU_get_number_of_failures();
	CU_cleanup_registry();

	return (int)fails;
}
