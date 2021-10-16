#include <stdlib.h>
#include <stdio.h>
#include "mosquitto.h"
#include "/usr/local/msquic/include/msquic.h"
#include "/usr/local/msquic/include/msquic_posix.h"

const QUIC_API_TABLE* MsQuic;
HQUIC Registration;


int main(int argc, char *argv[])
{
	int rc;
	struct mosquitto_message *msg;

    QUIC_STATUS Status;
    const char* ResumptionTicketString = NULL;
    HQUIC Connection = NULL;

    //
    // Allocate a new connection object.
    //
    if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration, NULL, NULL, &Connection))) {
        printf("ConnectionOpen failed, 0x%x!\n", Status);
        //goto Error;
    }


	mosquitto_lib_init();

	rc = mosquitto_subscribe_simple(
			&msg, 1, true,
			"irc/#", 0,
			"test.mosquitto.org", 1883,
			NULL, 60, true,
			NULL, NULL,
			NULL, NULL);

	if(rc){
		printf("Error: %s\n", mosquitto_strerror(rc));
		mosquitto_lib_cleanup();
		return rc;
	}

	printf("%s %s\n", msg->topic, (char *)msg->payload);
	mosquitto_message_free(&msg);

	mosquitto_lib_cleanup();

	return 0;
}

