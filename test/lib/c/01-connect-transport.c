#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <mosquitto.h>

static struct mosquitto *expected_mosq = NULL;
static const char *expected_obj = NULL;

static int open_calls = 0;
static int close_calls = 0;
static int opened_sock = -1;
static int closed_sock = -1;

/* Makes the next transport open callback fail instead of connecting. */
static int open_fail_rc = MOSQ_ERR_SUCCESS;
/* Makes the next transport open callback succeed but hand back no socket. */
static bool open_return_bad_sock = false;

static int run = -1;
static bool connected = false;
/* Cleared for the connection that mosquitto_destroy() tears down. */
static bool disconnect_when_connected = true;

/* Any check that fails exits straight away, without letting the client send
 * the DISCONNECT the test script is waiting for, so that a broken callback
 * fails the test rather than going unnoticed. */
#define CHECK(cond) \
	do{ \
		if(!(cond)){ \
			fprintf(stderr, "%s:%d: failed check: %s\n", __FILE__, __LINE__, #cond); \
			exit(1); \
		} \
	}while(0)


static int connect_to_broker(const char *port)
{
	struct addrinfo hints, *ainfo, *rp;
	int s = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if(getaddrinfo("localhost", port, &hints, &ainfo)){
		return -1;
	}
	for(rp = ainfo; rp != NULL; rp = rp->ai_next){
		s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(s == -1){
			continue;
		}
		if(connect(s, rp->ai_addr, rp->ai_addrlen) == 0){
			break;
		}
		close(s);
		s = -1;
	}
	freeaddrinfo(ainfo);
	return s;
}


static int on_transport_open(struct mosquitto *mosq, void *obj, int *sock)
{
	int s;

	CHECK(mosq == expected_mosq);
	CHECK(obj == expected_obj);

	open_calls++;

	if(open_fail_rc != MOSQ_ERR_SUCCESS){
		return open_fail_rc;
	}
	if(open_return_bad_sock){
		*sock = -1;
		return MOSQ_ERR_SUCCESS;
	}

	s = connect_to_broker(obj);
	if(s == -1){
		return MOSQ_ERR_ERRNO;
	}
	*sock = s;
	opened_sock = s;
	return MOSQ_ERR_SUCCESS;
}


static int on_transport_close(struct mosquitto *mosq, void *obj, int sock)
{
	CHECK(mosq == expected_mosq);
	CHECK(obj == expected_obj);
	/* Must be handed back the very socket the open callback returned. */
	CHECK(sock == opened_sock);

	close_calls++;
	closed_sock = sock;
	return close(sock);
}


static void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)obj;

	CHECK(rc == 0);
	connected = true;
	if(disconnect_when_connected){
		mosquitto_disconnect(mosq);
	}
}


static void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)mosq;
	(void)obj;

	run = rc;
}


/* Connect, let the broker accept and acknowledge, then disconnect. */
static void connect_and_disconnect(struct mosquitto *mosq)
{
	int rc;

	run = -1;
	connected = false;
	rc = mosquitto_connect_transport(mosq, 60, NULL);
	CHECK(rc == MOSQ_ERR_SUCCESS);

	while(run == -1){
		mosquitto_loop(mosq, -1, 1);
	}
	/* The disconnect callback must have been reached. */
	CHECK(run != -1);
}


int main(int argc, char *argv[])
{
	int rc;
	struct mosquitto *mosq;

	if(argc < 2){
		return 1;
	}

	mosquitto_lib_init();

	mosq = mosquitto_new("01-connect-transport", true, argv[1]);
	if(mosq == NULL){
		return 1;
	}
	expected_mosq = mosq;
	expected_obj = argv[1];

	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_disconnect_callback_set(mosq, on_disconnect);

	/* Must fail while no transport open callback is set, without reaching a
	 * callback to do so. */
	rc = mosquitto_connect_transport(mosq, 60, NULL);
	CHECK(rc == MOSQ_ERR_INVAL);
	CHECK(open_calls == 0);

	/* Setting only the close callback must not make it connectable either. */
	mosquitto_transport_close_callback_set(mosq, on_transport_close);
	rc = mosquitto_connect_transport(mosq, 60, NULL);
	CHECK(rc == MOSQ_ERR_INVAL);
	CHECK(open_calls == 0);
	CHECK(close_calls == 0);

	mosquitto_transport_open_callback_set(mosq, on_transport_open);

	/* An error from the open callback must reach the caller, and must not
	 * produce a close callback for a socket that was never opened. */
	open_fail_rc = MOSQ_ERR_PROXY;
	rc = mosquitto_connect_transport(mosq, 60, NULL);
	CHECK(rc == MOSQ_ERR_PROXY);
	CHECK(open_calls == 1);
	CHECK(close_calls == 0);
	open_fail_rc = MOSQ_ERR_SUCCESS;

	/* An open callback reporting success without a socket must be rejected,
	 * and again must not produce a close callback. */
	open_return_bad_sock = true;
	rc = mosquitto_connect_transport(mosq, 60, NULL);
	CHECK(rc == MOSQ_ERR_INVAL);
	CHECK(open_calls == 2);
	CHECK(close_calls == 0);
	open_return_bad_sock = false;

	/* Unsetting the open callback must take effect. */
	mosquitto_transport_open_callback_set(mosq, NULL);
	rc = mosquitto_connect_transport(mosq, 60, NULL);
	CHECK(rc == MOSQ_ERR_INVAL);
	CHECK(open_calls == 2);
	mosquitto_transport_open_callback_set(mosq, on_transport_open);

	/* First connection. */
	connect_and_disconnect(mosq);
	CHECK(open_calls == 3);
	CHECK(opened_sock >= 0);

	/* Disconnecting closed the connection, so the socket the open callback
	 * returned must have been handed back exactly once by now. Anything else
	 * exits here, before the second CONNECT the test script expects. */
	CHECK(close_calls == 1);
	CHECK(closed_sock == opened_sock);

	/* Second connection, over a freshly provided socket: the open callback is
	 * used again for a reconnection, and its socket closed again. */
	connect_and_disconnect(mosq);
	CHECK(open_calls == 4);
	CHECK(close_calls == 2);
	CHECK(closed_sock == opened_sock);

	/* Third connection, torn down by mosquitto_destroy() while still
	 * connected rather than by a disconnect: the socket must be handed back
	 * on that path too. */
	disconnect_when_connected = false;
	connected = false;
	rc = mosquitto_connect_transport(mosq, 60, NULL);
	CHECK(rc == MOSQ_ERR_SUCCESS);
	CHECK(open_calls == 5);
	while(!connected){
		mosquitto_loop(mosq, -1, 1);
	}
	CHECK(close_calls == 2);

	mosquitto_destroy(mosq);

	CHECK(open_calls == 5);
	CHECK(close_calls == 3);
	CHECK(closed_sock == opened_sock);

	mosquitto_lib_cleanup();
	return 0;
}
