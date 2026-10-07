/*
Copyright (c) 2023 Cedalo GmbH

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#define kMaxInputLength 100000
#include "fuzz_packet_read_base.h"


extern "C" int fuzz_acl_check(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_acl_check *ed = (struct mosquitto_evt_acl_check *)event_data;

	UNUSED(event);
	UNUSED(userdata);

	/* This is a check that is ultimately determined by the fuzz input data, so
	 * the fuzzer can discover how to access both the fail/success cases.
	 */
	if(ed->topic && (ed->topic[0]%2 == 0)){
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_AUTH;
	}
}


extern "C" int fuzz_packet_read_init(struct mosquitto *context)
{
	context->listener->security_options->pid = (mosquitto_plugin_id_t *)calloc(1, sizeof(mosquitto_plugin_id_t));
	if(!context->listener->security_options->pid){
		return 1;
	}
	mosquitto_callback_register(context->listener->security_options->pid,
			MOSQ_EVT_ACL_CHECK, fuzz_acl_check, NULL, NULL);

	return 0;
}


extern "C" void fuzz_packet_read_cleanup(struct mosquitto *context)
{
	mosquitto_callback_unregister(context->listener->security_options->pid,
			MOSQ_EVT_ACL_CHECK, fuzz_acl_check, NULL);

	free(context->listener->security_options->pid);
	context->listener->security_options->pid = NULL;
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	return fuzz_packet_read_base(data, size, handle__subscribe);
}
