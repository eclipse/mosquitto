/*
Copyright (c) 2020-2021 Roger Light <roger@atchoo.org>

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
   Akos Vandra-Meyer - addition of YAML file format
*/

#include "config.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <uthash.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "json_help.h"

#include "dynamic_security.h"


static int acl_cmp(struct dynsec__acl *a, struct dynsec__acl *b)
{
    return b->priority - a->priority;
}

static struct dynsec__acl* dynsec_acllist_find(struct dynsec__acl **acllist, char* topic) {
    if (!topic) return NULL;

    struct dynsec__acl *acl = NULL;

    HASH_FIND(hh, *acllist, topic, strlen(topic), acl);

    return acl;
}


bool dynsec_acllist__add(struct dynsec__acl **acllist, struct dynsec__acl *acl)
{
    if (dynsec_acllist_find(acllist, acl->topic) == NULL) {
        HASH_ADD_KEYPTR_INORDER(hh, *acllist, acl->topic, strlen(acl->topic), acl, acl_cmp);
        return true;
    } else {
        return false;
    }
}
