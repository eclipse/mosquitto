/*
Copyright (c) 2009-2015 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include <assert.h>

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "logging_mosq.h"
#include "mqtt3_protocol.h"
#include "send_mosq.h"

#ifdef WITH_BROKER
#  include "mosquitto_broker.h"
#endif


int send__disconnect(struct mosquitto *mosq)
{
	assert(mosq);
#ifdef WITH_BROKER
# ifdef WITH_BRIDGE
	log__printf(mosq, MOSQ_LOG_DEBUG, "Bridge %s sending DISCONNECT", mosq->id);
# endif
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s sending DISCONNECT", mosq->id);
#endif
	return send__simple_command(mosq, DISCONNECT);
}

