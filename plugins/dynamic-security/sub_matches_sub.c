/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR EDL-1.0

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *strtok_hier(char *str, char **saveptr)
{
	char *c;

	if(str != NULL){
		*saveptr = str;
	}

	if(*saveptr == NULL){
		return NULL;
	}

	c = strchr(*saveptr, '/');
	if(c){
		str = *saveptr;
		*saveptr = c+1;
		c[0] = '\0';
	}else if(*saveptr){
		/* No match, but surplus string */
		str = *saveptr;
		*saveptr = NULL;
	}
	return str;
}


static int count_hier_levels(const char *s)
{
	int count = 1;
	const char *c = s;

	while((c = strchr(c, '/')) && c[0]){
		c++;
		count++;
	}
	return count;
}


static bool hash_check(char *s, size_t *len)
{
	if((*len) == 1 && s[0] == '#'){
		s[0] = '\0';
		(*len)--;
		return true;
	}else if((*len) > 1 && s[(*len)-2] == '/' && s[(*len)-1] == '#'){
		s[(*len)-2] = '\0';
		s[(*len)-1] = '\0';
		(*len) -= 2;
		return true;
	}
	return false;
}


bool sub_acl_check(const char *acl, const char *sub)
{
	char *acl_local;
	char *sub_local;
	size_t acl_len, sub_len;
	bool acl_hash = false, sub_hash = false;
	int acl_levels, sub_levels;
	int i;
	char *acl_token, *sub_token;
	char *acl_saveptr, *sub_saveptr;

	acl_len = strlen(acl);
	if(acl_len == 1 && acl[0] == '#'){
		return true;
	}

	sub_len = strlen(sub);
	//mosquitto_validate_utf8(acl, acl_len);

	acl_local = strdup(acl);
	sub_local = strdup(sub);
	if(acl_local == NULL || sub_local == NULL){
		free(acl_local);
		free(sub_local);
		return false;
	}

	acl_hash = hash_check(acl_local, &acl_len);
	sub_hash = hash_check(sub_local, &sub_len);

	if(sub_hash == true && acl_hash == false){
		free(acl_local);
		free(sub_local);
		return false;
	}

	acl_levels = count_hier_levels(acl_local);
	sub_levels = count_hier_levels(sub_local);
	if(acl_levels > sub_levels){
		free(acl_local);
		free(sub_local);
		return false;
	}else if(sub_levels > acl_levels){
		if(acl_hash == false){
			free(acl_local);
			free(sub_local);
			return false;
		}
	}

	acl_saveptr = acl_local;
	sub_saveptr = sub_local;
	for(i=0; i<sub_levels; i++){
		acl_token = strtok_hier(acl_saveptr, &acl_saveptr);
		sub_token = strtok_hier(sub_saveptr, &sub_saveptr);

		if(i<acl_levels &&
				(!strcmp(acl_token, "+")
				 || !strcmp(acl_token, sub_token))){

			/* This level matches a single level wildcard, or is an exact
			 * match, so carry on checking. */
		}else if(i>=acl_levels && acl_hash == true){
			/* The sub has more levels of hierarchy than the acl, but the acl
			 * ends in a multi level wildcard so the match is fine. */
		}else{
			free(acl_local);
			free(sub_local);
			return false;
		}
	}

	free(acl_local);
	free(sub_local);
	return true;
}


#ifdef TEST

#define BLK "\e[0;30m"
#define RED "\e[0;31m"
#define GRN "\e[0;32m"
#define YEL "\e[0;33m"
#define BLU "\e[0;34m"
#define MAG "\e[0;35m"
#define CYN "\e[0;36m"
#define WHT "\e[0;37m"
#define RST "\e[0m"

void hier_test(const char *s, int expected)
{
	int levels;

	levels = count_hier_levels(s);
	printf("HIER %s %d:%d ", s, expected, levels);
	if(levels == expected){
		printf(GRN "passed" RST "\n");
	}else{
		printf(RED "failed" RST "\n");
	}
}

void test(const char *sub1, const char *sub2, bool expected)
{
	bool result;

	printf("ACL %s : %s ", sub1, sub2);
	result = sub_acl_check(sub1, sub2);
	if(result == expected){
		printf(GRN "passed\n" RST);
	}else{
		printf(RED "failed\n" RST);
	}
}


int main(int argc, char *argv[])
{
	hier_test("foo/+/bar", 3);
	hier_test("foo/#", 2);
	hier_test("foo/+/ba℞/#", 4);
	hier_test("foo/baz/ba℞", 3);
	hier_test("foo/+/ba℞/#", 4);
	hier_test("foo/baz/ba℞/+", 4);
	hier_test("foo/+/ba℞/#", 4);
	hier_test("foo/baz/ba℞/#", 4);
	hier_test("foo/+/ba℞/#", 4);
	hier_test("foo/baz/+/#", 4);
	hier_test("/+//#", 4);
	hier_test("/foo///#", 5);
	hier_test("#", 1);
	hier_test("+", 1);
	hier_test("/", 2);
	hier_test("////////////////////////////////////////////////////////////////////////////////////////////////////", 101);

	test("foo/+/bar", "foo/#", false);
	test("foo/+/ba℞/#", "foo/baz/ba℞", true);
	test("foo/+/ba℞/#", "foo/baz/ba℞/+", true);
	test("foo/+/ba℞/#", "foo/baz/ba℞/#", true);
	test("foo/+/ba℞/#", "foo/baz/+/#", false);
	test("/+//#", "/foo///#", true);
	test("#", "#", true);
	test("#", "+", true);
	test("/#", "+", false);
	test("/#", "/+", true);
	test("/+", "#", false);
	test("/+", "+", false);
	test("+/+", "topic/topic", true);
	test("+/+", "topic/topic/", false);
	test("+", "#", false);
	test("+", "+", true);
	test("a/b/c/d/e", "a/b/c/d/e", true);
	test("a/b/ /d/e", "a/b/c/d/e", false);

	return 0;
}
#endif
