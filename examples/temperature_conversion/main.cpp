#include "temperature_conversion.h"

int main(int argc, char *argv[])
{
	class mqtt_tempconv *tempconv;
	int rc;

	mosqpp::lib_init();

	tempconv = new mqtt_tempconv("tempconv", "localhost", 1883);
	tempconv->loop_forever();

	mosqpp::lib_cleanup();

	return 0;
}

