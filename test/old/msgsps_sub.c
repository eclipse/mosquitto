/* This provides a crude manner of testing the performance of a broker in messages/s. */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <mosquitto.h>
#include <stdatomic.h>

#include <msgsps_common.h>

static atomic_int message_count = 0;

void my_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg)
{
	message_count++;
}

int main(int argc, char *argv[])
{
	struct mosquitto *mosq;
	int c;

	mosquitto_lib_init();

	mosq = mosquitto_new(NULL, true, NULL);
	mosquitto_message_callback_set(mosq, my_message_callback);

	mosquitto_connect(mosq, HOST, PORT, 600);
	mosquitto_subscribe(mosq, NULL, "perf/test", SUB_QOS);

	mosquitto_loop_start(mosq);
	while(1){
		sleep(1);
		c = message_count;
		message_count = 0;
		printf("%d\n", c);

	}

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();

	return 0;
}
