/*
Copyright (c) 2016-2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
SPDX-License-Identifier: EPL-2.0 OR EDL-1.0

Contributors:
   Roger Light - initial implementation.
*/

#include "config.h"

#include <stdio.h>
#include "mosquitto.h"

int mosquitto_validate_utf8(const char *str, int len)
{
	int i;
	int j;
	int codelen;
	int codepoint;
	const unsigned char *ustr = (const unsigned char *)str;

	if(!str) return MOSQ_ERR_INVAL;
	if(len < 0 || len > 65536) return MOSQ_ERR_INVAL;

	for(i=0; i<len; i++){
		if(ustr[i] == 0){
			return MOSQ_ERR_MALFORMED_UTF8;
		}else if(ustr[i] <= 0x7f){
			codelen = 1;
			codepoint = ustr[i];
		}else if((ustr[i] & 0xE0) == 0xC0){
			/* 110xxxxx - 2 byte sequence */
			if(ustr[i] == 0xC0 || ustr[i] == 0xC1){
				/* Invalid bytes */
				return MOSQ_ERR_MALFORMED_UTF8;
			}
			codelen = 2;
			codepoint = (ustr[i] & 0x1F);
		}else if((ustr[i] & 0xF0) == 0xE0){
			/* 1110xxxx - 3 byte sequence */
			codelen = 3;
			codepoint = (ustr[i] & 0x0F);
		}else if((ustr[i] & 0xF8) == 0xF0){
			/* 11110xxx - 4 byte sequence */
			if(ustr[i] > 0xF4){
				/* Invalid, this would produce values > 0x10FFFF. */
				return MOSQ_ERR_MALFORMED_UTF8;
			}
			codelen = 4;
			codepoint = (ustr[i] & 0x07);
		}else{
			/* Unexpected continuation byte. */
			return MOSQ_ERR_MALFORMED_UTF8;
		}

		/* Reconstruct full code point */
		if(i == len-codelen+1){
			/* Not enough data */
			return MOSQ_ERR_MALFORMED_UTF8;
		}
		for(j=0; j<codelen-1; j++){
			if((ustr[++i] & 0xC0) != 0x80){
				/* Not a continuation byte */
				return MOSQ_ERR_MALFORMED_UTF8;
			}
			codepoint = (codepoint<<6) | (ustr[i] & 0x3F);
		}
		
		/* Check for UTF-16 high/low surrogates */
		if(codepoint >= 0xD800 && codepoint <= 0xDFFF){
			return MOSQ_ERR_MALFORMED_UTF8;
		}

		/* Check for overlong or out of range encodings */
		/* Checking codelen == 2 isn't necessary here, because it is already
		 * covered above in the C0 and C1 checks.
		 * if(codelen == 2 && codepoint < 0x0080){
		 *	 return MOSQ_ERR_MALFORMED_UTF8;
		 * }else
		*/
		if(codelen == 3 && codepoint < 0x0800){
			return MOSQ_ERR_MALFORMED_UTF8;
		}else if(codelen == 4 && (codepoint < 0x10000 || codepoint > 0x10FFFF)){
			return MOSQ_ERR_MALFORMED_UTF8;
		}

		/* Check for non-characters */
		if(codepoint >= 0xFDD0 && codepoint <= 0xFDEF){
			return MOSQ_ERR_MALFORMED_UTF8;
		}
		if((codepoint & 0xFFFF) == 0xFFFE || (codepoint & 0xFFFF) == 0xFFFF){
			return MOSQ_ERR_MALFORMED_UTF8;
		}
		/* Check for control characters */
		if(codepoint <= 0x001F || (codepoint >= 0x007F && codepoint <= 0x009F)){
			return MOSQ_ERR_MALFORMED_UTF8;
		}
	}
	return MOSQ_ERR_SUCCESS;
}

