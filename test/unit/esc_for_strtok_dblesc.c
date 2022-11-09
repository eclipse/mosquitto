#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include <misc_mosq.h>

#include <stdlib.h>

static void esc_for_strtok_dblesc_helper(const char *plain, const char *delim, const char *expected)
{
	char *res;

	res = esc_for_strtok_dblesc(plain, delim);
	CU_ASSERT_PTR_NOT_NULL(res);
	if(res){
		CU_ASSERT_STRING_EQUAL(res, expected);
		free(res);
	}
}


static void TEST_null_input(void)
{
	char *res;

	res = esc_for_strtok_dblesc(NULL, ":,");
	CU_ASSERT_PTR_NULL(res);

	res = esc_for_strtok_dblesc("some string", NULL);
	CU_ASSERT_PTR_NULL(res);
}


static void TEST_empty_input(void)
{
	esc_for_strtok_dblesc_helper("", ":,", "");
}


static void TEST_empty_delim(void)
{
	esc_for_strtok_dblesc_helper("some string", "", "some string");
}


static void TEST_no_dbl_1(void)
{
	esc_for_strtok_dblesc_helper("abc", ":", "abc");
}


static void TEST_no_dbl_2(void)
{
	esc_for_strtok_dblesc_helper("abc", ",;:", "abc");
}


static void TEST_dbl_1(void)
{
	esc_for_strtok_dblesc_helper("a:b:c", ":", "a::b::c");
}


static void TEST_dbl_2(void)
{
	esc_for_strtok_dblesc_helper(":a:b:c:", ":", "::a::b::c::");
}


static void TEST_dbl_3(void)
{
	esc_for_strtok_dblesc_helper("abc,def;ghi:", ":,;", "abc,,def;;ghi::");
}


static void TEST_dbl_4(void)
{
	esc_for_strtok_dblesc_helper(":::,,,;;;", ";:,", "::::::,,,,,,;;;;;;");
}


/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */

int init_misc_esc_for_strtok_dblesc_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("Misc esc_for_strtok_dblesc", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit Misc esc_for_strtok_dblesc test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Null input", TEST_null_input)
			|| !CU_add_test(test_suite, "Empty input", TEST_empty_input)
			|| !CU_add_test(test_suite, "Empty delim", TEST_empty_delim)
			|| !CU_add_test(test_suite, "No double delimiters 1", TEST_no_dbl_1)
			|| !CU_add_test(test_suite, "No double delimiters 2", TEST_no_dbl_2)
			|| !CU_add_test(test_suite, "Double delimiters 1", TEST_dbl_1)
			|| !CU_add_test(test_suite, "Double delimiters 2", TEST_dbl_2)
			|| !CU_add_test(test_suite, "Double delimiters 3", TEST_dbl_3)
			|| !CU_add_test(test_suite, "Double delimiters 4", TEST_dbl_4)
			){

		printf("Error adding Misc esc_for_strtok_dblesc CUnit tests.\n");
		return 1;
	}

	return 0;
}
