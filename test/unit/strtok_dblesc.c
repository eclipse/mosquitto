#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include <misc_mosq.h>


static void strtok_dblesc_helper(char *buf, const char *delim, const char *expect1, const char *expect2, const char *expect3)
{
	char *res;
	char *saveptr;

	res = strtok_dblesc(buf, delim, &saveptr);
	CU_ASSERT_PTR_NOT_NULL(res);
	if(res){
		CU_ASSERT_STRING_EQUAL(res, expect1);
	}

	res = strtok_dblesc(NULL, delim, &saveptr);
	CU_ASSERT_PTR_NOT_NULL(res);
	if(res){
		CU_ASSERT_STRING_EQUAL(res, expect2);
	}

	res = strtok_dblesc(NULL, delim, &saveptr);
	CU_ASSERT_PTR_NOT_NULL(res);
	if(res){
		CU_ASSERT_STRING_EQUAL(res, expect3);
	}

	res = strtok_dblesc(NULL, delim, &saveptr);
	CU_ASSERT_PTR_NULL(res);
}


static void TEST_null_input(void)
{
	char *res;
	char *saveptr = NULL;
	char buf[] = "a:b";

	res = strtok_dblesc(NULL, ":", &saveptr);
	CU_ASSERT_PTR_NULL(res);

	res = strtok_dblesc(buf, NULL, &saveptr);
	CU_ASSERT_PTR_NULL(res);

	res = strtok_dblesc(buf, ":", NULL);
	CU_ASSERT_PTR_NULL(res);
}


static void TEST_empty_input(void)
{
	char buf[] = "";
	char *res;
	char *saveptr;

	res = strtok_dblesc(buf, ":", &saveptr);
	CU_ASSERT_PTR_NULL(res);
}


static void TEST_empty_delim(void)
{
	char buf[] = "abc";
	char *res;
	char *saveptr;

	res = strtok_dblesc(buf, "", &saveptr);
	CU_ASSERT_PTR_NOT_NULL(res);
	if(res){
		CU_ASSERT_STRING_EQUAL(res, "abc");
	}

	res = strtok_dblesc(NULL, "", &saveptr);
	CU_ASSERT_PTR_NULL(res);
}


static void TEST_no_dbl_1(void)
{
	char buf[] = "abc:def:ghi";
	strtok_dblesc_helper(buf, ":", "abc", "def", "ghi");
}


static void TEST_no_dbl_2(void)
{
	char buf[] = "abc:def,ghi";
	strtok_dblesc_helper(buf, ":,", "abc", "def", "ghi");
}


static void TEST_diff_delim(void)
{
	char buf[] = ":abc:,;:def,ghi,";
	strtok_dblesc_helper(buf, ":,;", "abc", "def", "ghi");
}


static void TEST_dbl_1(void)
{
	char buf[] = "a::bc:de::f:g::h::i";
	strtok_dblesc_helper(buf, ":", "a:bc", "de:f", "g:h:i");
}


static void TEST_dbl_2(void)
{
	char buf[] = "::abc:def:ghi::";
	strtok_dblesc_helper(buf, ":,", ":abc", "def", "ghi:");
}


static void TEST_dbl_3(void)
{
	char buf[] = ":::::::,,,,,,,::::::";
	strtok_dblesc_helper(buf, ":,", ":::", ",,,", ":::");
}


/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */

int init_misc_strtok_dblesc_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("Misc strtok_dblesc", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit Misc strtok_dblesc test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Null input", TEST_null_input)
			|| !CU_add_test(test_suite, "Empty input", TEST_empty_input)
			|| !CU_add_test(test_suite, "Empty delim", TEST_empty_delim)
			|| !CU_add_test(test_suite, "No double delimiters 1", TEST_no_dbl_1)
			|| !CU_add_test(test_suite, "No double delimiters 2", TEST_no_dbl_2)
			|| !CU_add_test(test_suite, "Different delimiters", TEST_diff_delim)
			|| !CU_add_test(test_suite, "Double delimiters 1", TEST_dbl_1)
			|| !CU_add_test(test_suite, "Double delimiters 2", TEST_dbl_2)
			|| !CU_add_test(test_suite, "Double delimiters 3", TEST_dbl_3)
			){

		printf("Error adding Misc strtok_dblesc CUnit tests.\n");
		return 1;
	}

	return 0;
}
