#include <stdio.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#ifndef WIN32
#  include <unistd.h>
#endif
#include <stdlib.h>

#include "mosquitto.h"

#define ALLOW_SYMLINKS "MOSQUITTO_UNSAFE_ALLOW_SYMLINKS"
#define SYMLINK "test_symlink"
#define DATAFILE "test_data"

#ifndef WIN32


static bool symlink_test_init(void)
{
	unsetenv(ALLOW_SYMLINKS);

	/* Create a file to open */
	FILE *fptr = mosquitto_fopen(DATAFILE, "wb", false);
	CU_ASSERT_PTR_NOT_NULL(fptr);
	if(!fptr){
		return false;
	}
	fclose(fptr);

	/* Add a symlink */
	int rc = symlink(DATAFILE, SYMLINK);
	CU_ASSERT_EQUAL(rc, 0);
	return rc == 0?true:false;
}


static void symlink_test_cleanup(void)
{
	unlink(SYMLINK);
	unlink(DATAFILE);
	unsetenv(ALLOW_SYMLINKS);
}
#endif


#ifndef WIN32


static void TEST_restrict_read_default(void)
{
	FILE *fptr;

	if(!symlink_test_init()){
		return;
	}

	/* No restrict read, so symlink ok */
	fptr = mosquitto_fopen(SYMLINK, "rb", false);
	CU_ASSERT_PTR_NOT_NULL(fptr);
	if(fptr){
		fclose(fptr);
	}

	/* Restricted read, so symlink not allowed */
	fptr = mosquitto_fopen(SYMLINK, "rb", true);
	CU_ASSERT_PTR_NULL(fptr);
	if(fptr){
		fclose(fptr);
	}

	symlink_test_cleanup();
}


static void TEST_restrict_read_with_symlinks(void)
{
	FILE *fptr;

	if(!symlink_test_init()){
		return;
	}

	int rc = setenv(ALLOW_SYMLINKS, "1", true);
	CU_ASSERT_EQUAL(rc, 0);

	/* No restrict read, so symlink ok */
	fptr = mosquitto_fopen(SYMLINK, "rb", false);
	CU_ASSERT_PTR_NOT_NULL(fptr);
	if(fptr){
		fclose(fptr);
	}

	/* Restricted read but with override so symlink ok */
	fptr = mosquitto_fopen(SYMLINK, "rb", true);
	CU_ASSERT_PTR_NOT_NULL(fptr);
	if(fptr){
		fclose(fptr);
	}

	symlink_test_cleanup();
}
#endif


/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */


int init_file_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("file", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit file test suite.\n");
		return 1;
	}

	if(0
#ifndef WIN32
			|| !CU_add_test(test_suite, "Restrict read default", TEST_restrict_read_default)
			|| !CU_add_test(test_suite, "Restrict read with symlinks", TEST_restrict_read_with_symlinks)
#endif
			){

		printf("Error adding file CUnit tests.\n");
		return 1;
	}

	return 0;
}
