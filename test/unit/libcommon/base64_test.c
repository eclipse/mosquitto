#include <stdio.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "mosquitto/mqtt_protocol.h"
#include "property_common.h"


//int mosquitto_base64_encode(const unsigned char *in, size_t in_len, char **encoded);


//int mosquitto_base64_decode(const char *in, unsigned char **decoded, unsigned int *decoded_len);


#ifdef WITH_TLS


static void check_encode(const char *input, size_t in_len, const char *expected_output)
{
	char *encoded;
	int rc = mosquitto_base64_encode((const unsigned char *)input, in_len, &encoded);

	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_STRING_EQUAL(encoded, expected_output);
	if(strcmp(encoded, expected_output)){
		printf("%s || %s\n", encoded, expected_output);
	}
	mosquitto_free(encoded);
}


static void check_decode(const char *input, int expected_rc, const char *expected_output, unsigned int expected_len)
{
	unsigned char *decoded;
	unsigned int len;
	int rc = mosquitto_base64_decode(input, &decoded, &len);

	CU_ASSERT_EQUAL(rc, expected_rc);
	if(rc != expected_rc){
		printf("rc: %d||%d\n", rc, expected_rc);
	}
	if(len != expected_len){
		printf("len: %d||%d\n", len, expected_len);
	}
	CU_ASSERT_EQUAL(len, expected_len);
	if(decoded){
		CU_ASSERT_EQUAL(memcmp(decoded, expected_output, len), 0);
		mosquitto_free(decoded);
	}
}


static void TEST_encode_empty(void)
{
	check_encode("", 0, "");
}


static void TEST_encode_string_lengths(void)
{
	check_encode("a", 1, "YQ==");
	check_encode("ab", 2, "YWI=");
	check_encode("abc", 3, "YWJj");
	check_encode("abcd", 4, "YWJjZA==");
	check_encode("abcde", 5, "YWJjZGU=");
	check_encode("abcdef", 6, "YWJjZGVm");
	check_encode("abcdefg", 7, "YWJjZGVmZw==");
}


static void TEST_encode_binary(void)
{
	const char a[1] = {0};
	const char b[2] = {0, 1};
	const char c[3] = {0, 1, 2};
	const char d[4] = {0, 1, 2, 3};
	const char e[5] = {0, 1, 2, 3, 4};
	const char f[6] = {0, 1, 2, 3, 4, 5};
	const char g[7] = {0, 1, 2, 3, 4, 5, 6};

	check_encode(a, 1, "AA==");
	check_encode(b, 2, "AAE=");
	check_encode(c, 3, "AAEC");
	check_encode(d, 4, "AAECAw==");
	check_encode(e, 5, "AAECAwQ=");
	check_encode(f, 6, "AAECAwQF");
	check_encode(g, 7, "AAECAwQFBg==");
}


static void TEST_decode_empty(void)
{
	check_decode("", 1, "", 0);
}


static void TEST_decode_invalid(void)
{
	check_decode("abc", 1, "", 0);
}


static void TEST_decode_string_lengths(void)
{
	check_decode("YQ==", MOSQ_ERR_SUCCESS, "a", 1);
	check_decode("YWI=", MOSQ_ERR_SUCCESS, "ab", 2);
	check_decode("YWJj", MOSQ_ERR_SUCCESS, "abc", 3);
	check_decode("YWJjZA==", MOSQ_ERR_SUCCESS, "abcd", 4);
	check_decode("YWJjZGU=", MOSQ_ERR_SUCCESS, "abcde", 5);
	check_decode("YWJjZGVm", MOSQ_ERR_SUCCESS, "abcdef", 6);
	check_decode("YWJjZGVmZw==", MOSQ_ERR_SUCCESS, "abcdefg", 7);
}


static void TEST_decode_binary(void)
{
	const char a[1] = {0};
	const char b[2] = {0, 1};
	const char c[3] = {0, 1, 2};
	const char d[4] = {0, 1, 2, 3};
	const char e[5] = {0, 1, 2, 3, 4};
	const char f[6] = {0, 1, 2, 3, 4, 5};
	const char g[7] = {0, 1, 2, 3, 4, 5, 6};

	check_decode("AA==", MOSQ_ERR_SUCCESS, a, 1);
	check_decode("AAE=", MOSQ_ERR_SUCCESS, b, 2);
	check_decode("AAEC", MOSQ_ERR_SUCCESS, c, 3);
	check_decode("AAECAw==", MOSQ_ERR_SUCCESS, d, 4);
	check_decode("AAECAwQ=", MOSQ_ERR_SUCCESS, e, 5);
	check_decode("AAECAwQF", MOSQ_ERR_SUCCESS, f, 6);
	check_decode("AAECAwQFBg==", MOSQ_ERR_SUCCESS, g, 7);
}


/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */


int init_base64_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("base64", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit base64 test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Encode Empty", TEST_encode_empty)
			|| !CU_add_test(test_suite, "Encode String lengths", TEST_encode_string_lengths)
			|| !CU_add_test(test_suite, "Encode Binary", TEST_encode_binary)
			|| !CU_add_test(test_suite, "Decode Empty", TEST_decode_empty)
			|| !CU_add_test(test_suite, "Decode Invalid", TEST_decode_invalid)
			|| !CU_add_test(test_suite, "Decode String lengths", TEST_decode_string_lengths)
			|| !CU_add_test(test_suite, "Decode Binary", TEST_decode_binary)
			){

		printf("Error adding Property Add CUnit tests.\n");
		return 1;
	}

	return 0;
}
#endif
