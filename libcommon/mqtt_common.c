/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

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

#include "config.h"

#include <stdint.h>

#include "mosquitto.h"


unsigned int mosquitto_varint_bytes(uint32_t word)
{
	if(word < 128){
		return 1;
	}else if(word < 16384){
		return 2;
	}else if(word < 2097152){
		return 3;
	}else if(word < 268435456){
		return 4;
	}else{
		return 5;
	}
}
