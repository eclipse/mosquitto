#include "config.h"
#include <stdio.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

int init_base64_tests(void);
int init_file_tests(void);
int init_property_add_tests(void);
int init_property_value_tests(void);
int init_strings_tests(void);
int init_topic_tests(void);
int init_trim_tests(void);
int init_utf8_tests(void);


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
#ifdef WITH_TLS
			|| init_base64_tests()
#endif
			|| init_file_tests()
			|| init_property_add_tests()
			|| init_property_value_tests()
			|| init_strings_tests()
			|| init_topic_tests()
			|| init_trim_tests()
			|| init_utf8_tests()
			){

		CU_cleanup_registry();
		return 1;
	}

	CU_basic_set_mode(CU_BRM_NORMAL);
	CU_basic_run_tests();
	fails = CU_get_number_of_failures();
	CU_cleanup_registry();

	return (int)fails;
}

