#ifndef QUIC_CLIENT_H
#define QUIC_CLIENT_H

#include </usr/local/msquic/include/msquic.h>
#include </usr/local/msquic/include/msquic_posix.h>
#include "common.h"
#include "mosquitto_internal.h"


bool Connected; // TODO: remove

int quic_connect(const char *host, uint16_t port, struct mosquitto *mosq);

#endif // QUIC_CLIENT_H