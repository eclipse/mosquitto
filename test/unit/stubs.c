#include <time.h>
#include <logging_mosq.h>

struct mosquitto_db{

};

int log__printf(struct mosquitto *mosq, unsigned int priority, const char *fmt, ...)
{
	return 0;
}

time_t mosquitto_time(void)
{
	return 123;
}

int net__socket_close(struct mosquitto_db *db, struct mosquitto *mosq)
{
	return MOSQ_ERR_SUCCESS;
}

int send__pingreq(struct mosquitto *mosq)
{
	return MOSQ_ERR_SUCCESS;
}

