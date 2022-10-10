/* This provides a crude manner of testing the performance of a broker in messages/s. */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mosquitto.h>
#include <stdatomic.h>

#include <msgsps_common.h>

static atomic_int message_count = 0;

void my_publish_callback(struct mosquitto *mosq, void *obj, int mid)
{
	message_count++;
}

int main(int argc, char *argv[])
{
	struct mosquitto *mosq;
	int i;
	uint8_t buf[MESSAGE_SIZE];

	mosquitto_lib_init();

	mosq = mosquitto_new(NULL, true, NULL);
	mosquitto_publish_callback_set(mosq, my_publish_callback);
	mosquitto_connect(mosq, HOST, PORT, 600);
	mosquitto_loop_start(mosq);

	i=0;
	while(1){
		mosquitto_publish(mosq, NULL, "perf/test", sizeof(buf), buf, PUB_QOS, false);
		usleep(100);
		i++;
		if(i == 10000){
			/* Crude "messages per second" count */
			i = message_count;
			message_count = 0;
			printf("%d\n", i);
			i = 0;
		}
	}
	mosquitto_loop_stop(mosq, false);
	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();

	return 0;
}
