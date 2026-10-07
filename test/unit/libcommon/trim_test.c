#include <stdio.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include <mosquitto.h>


static void rtrim_helper(const char *expected, char *buf)
{
	char *res;

	res = mosquitto_trimblanks(buf);
	CU_ASSERT_PTR_NOT_NULL(res);
	if(res){
		CU_ASSERT_EQUAL(strlen(buf), strlen(res));
		CU_ASSERT_STRING_EQUAL(res, expected);
		CU_ASSERT_PTR_EQUAL(res, buf);
	}
}


static void ltrim_helper(const char *expected, char *buf)
{
	char *res;

	res = mosquitto_trimblanks(buf);
	CU_ASSERT_PTR_NOT_NULL(res);
	if(res){
		CU_ASSERT_EQUAL(strlen(expected), strlen(res));
		CU_ASSERT_STRING_EQUAL(res, expected);
	}
}


static void TEST_null_input(void)
{
	char *res;

	res = mosquitto_trimblanks(NULL);
	CU_ASSERT_PTR_NULL(res);
}


static void TEST_empty_input(void)
{
	char buf[10];
	char *res;

	memset(buf, 0, sizeof(buf));
	res = mosquitto_trimblanks(buf);
	CU_ASSERT_PTR_NOT_NULL(res);
	if(res){
		CU_ASSERT_STRING_EQUAL(res, "");
	}
}


static void TEST_no_blanks(void)
{
	char buf[10] = "noblanks";

	rtrim_helper("noblanks", buf);
}


static void TEST_rtrim(void)
{
	char buf1[20] = "spaces ";
	char buf2[20] = "spaces  ";
	char buf3[20] = "spaces   ";
	char buf4[20] = "spaces    ";
	char buf5[20] = "tabs\t";
	char buf6[20] = "tabs\t\t";
	char buf7[20] = "tabs\t\t\t";
	char buf8[20] = "tabs\t\t\t\t";
	char buf9[20] = "mixed \t";
	char buf10[20] = "mixed\t ";
	char buf11[20] = "mixed\t\t ";
	char buf12[20] = "mixed \t \t ";

	rtrim_helper("spaces", buf1);
	rtrim_helper("spaces", buf2);
	rtrim_helper("spaces", buf3);
	rtrim_helper("spaces", buf4);
	rtrim_helper("tabs", buf5);
	rtrim_helper("tabs", buf6);
	rtrim_helper("tabs", buf7);
	rtrim_helper("tabs", buf8);
	rtrim_helper("mixed", buf9);
	rtrim_helper("mixed", buf10);
	rtrim_helper("mixed", buf11);
	rtrim_helper("mixed", buf12);
}


static void TEST_ltrim(void)
{
	char buf1[20] = " spaces";
	char buf2[20] = "  spaces";
	char buf3[20] = "   spaces";
	char buf4[20] = "    spaces";
	char buf5[20] = "\ttabs";
	char buf6[20] = "\t\ttabs";
	char buf7[20] = "\t\t\ttabs";
	char buf8[20] = "\t\t\t\ttabs";
	char buf9[20] = "\t mixed";
	char buf10[20] = " \tmixed";
	char buf11[20] = " \t\tmixed";
	char buf12[20] = "\t \t mixed";

	ltrim_helper("spaces", buf1);
	ltrim_helper("spaces", buf2);
	ltrim_helper("spaces", buf3);
	ltrim_helper("spaces", buf4);
	ltrim_helper("tabs", buf5);
	ltrim_helper("tabs", buf6);
	ltrim_helper("tabs", buf7);
	ltrim_helper("tabs", buf8);
	ltrim_helper("mixed", buf9);
	ltrim_helper("mixed", buf10);
	ltrim_helper("mixed", buf11);
	ltrim_helper("mixed", buf12);
}


static void TEST_btrim(void)
{
	char buf1[20] = " spaces ";
	char buf2[20] = "  spaces  ";
	char buf3[20] = "   spaces   ";
	char buf4[20] = "    spaces    ";
	char buf5[20] = "\ttabs\t";
	char buf6[20] = "\t\ttabs\t\t";
	char buf7[20] = "\t\t\ttabs\t\t\t";
	char buf8[20] = "\t\t\t\ttabs\t\t\t\t";
	char buf9[20] = "\t mixed \t";
	char buf10[20] = " \tmixed\t ";
	char buf11[20] = " \t\tmixed\t\t ";
	char buf12[20] = "\t \t mixed \t \t ";

	ltrim_helper("spaces", buf1);
	ltrim_helper("spaces", buf2);
	ltrim_helper("spaces", buf3);
	ltrim_helper("spaces", buf4);
	ltrim_helper("tabs", buf5);
	ltrim_helper("tabs", buf6);
	ltrim_helper("tabs", buf7);
	ltrim_helper("tabs", buf8);
	ltrim_helper("mixed", buf9);
	ltrim_helper("mixed", buf10);
	ltrim_helper("mixed", buf11);
	ltrim_helper("mixed", buf12);
}


/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */


int init_trim_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("String trim", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit string trim test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Null input", TEST_null_input)
			|| !CU_add_test(test_suite, "Empty input", TEST_empty_input)
			|| !CU_add_test(test_suite, "No blanks", TEST_no_blanks)
			|| !CU_add_test(test_suite, "Right trim", TEST_rtrim)
			|| !CU_add_test(test_suite, "Left trim", TEST_ltrim)
			|| !CU_add_test(test_suite, "Both trim", TEST_btrim)
			){

		printf("Error adding string trim CUnit tests.\n");
		return 1;
	}

	return 0;
}
