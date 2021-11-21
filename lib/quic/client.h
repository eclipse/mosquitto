#ifndef QUIC_CLIENT_H
#define QUIC_CLIENT_H

#include <msquic.h>
#include <msquic_posix.h>
#include "common.h"
#include "mosquitto_internal.h"


bool Connected; // TODO: remove

int quic_connect(const char *host, uint16_t port, struct mosquitto *mosq);
int quic_disconnect(struct mosquitto *mosq);

#endif // QUIC_CLIENT_H