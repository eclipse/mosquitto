# Mosquitto Dynamic Security

This document describes a topic based mechanism for controlling security in
Mosquitto. JSON commands are published to topics like `$CONTROL/<feature>/v1`

## Clients

When a client connects to Mosquitto, it can optionally provide a username. The
username maps the client instance to a client on the broker, if it exists.
Multiple clients can make use of the same username, and hence the same broker
client.

## Groups

Broker clients can be defined as belonging to zero or more broker groups.

## Roles

Roles can be applied to a client or a group, and define what that client/group
is allowed to do, for example what topics it may or may not publish or
subscribe to.

## Publish limits

Roles can optionally impose a maximum payload size and a publish rate limit:

```json
{
	"command": "modifyRole",
	"rolename": "device",
	"maxPublishSize": 65536,
	"publishRateLimit": {"messages": 50, "perSeconds": 1, "burst": 200}
}
```

These properties are accepted by `createRole` and `modifyRole`, returned by
`getRole` and verbose `listRoles`, and saved in the configuration file. Omitted
properties leave the existing policy unchanged when modifying a role. Set
`maxPublishSize` to `0` or `publishRateLimit` to `null` to disable that limit.
The size counts payload bytes, excluding the topic, MQTT properties, and packet
headers. It must be an integer from 0 to 268435455. All three rate parameters
must be integers from 1 to 2147483647.

Rate limits use token buckets. Each account starts with `burst` tokens and
receives `messages / perSeconds` tokens per elapsed second, capped at `burst`.
Refilling uses the broker's monotonic time source with one-second resolution.
Each accepted incoming publish consumes one token from each applicable role.
All direct and group roles apply, irrespective of ACL priority; assigning the
same role through multiple paths consumes only one token. A message rejected
by any limit consumes no tokens. The normal ACL checks still apply.

Accounts have independent buckets for each role. All connections sharing a
username share that account's quota, including across reconnects. Anonymous
group roles also apply, with a separate bucket per anonymous connection; these
quotas reset on disconnect and do not prevent reconnect-based evasion. Use
authenticated accounts when quotas must survive reconnects. Runtime buckets
are cleared when their role's limits change, when the role or account is
deleted, or when the broker restarts. Unrelated metadata changes retain quotas.

Over-limit messages are discarded. MQTT 5 QoS 1 and 2 publishes receive PUBACK
or PUBREC with `0x97` (Quota exceeded). `0x96` (Message rate too high) is a
DISCONNECT reason code and cannot be used in PUBACK/PUBREC. MQTT 3 clients
receive the normal acknowledgement without delivery, because that protocol
cannot express a negative publish acknowledgement. QoS 0 messages are silently
dropped. The plugin logs a warning with the rejecting role, account, and reason.
Warnings are limited to one per minute for each role/account bucket, with the
number of messages rejected since its previous warning. Size and rate
rejections share this warning interval. Changing a role's limits resets its
buckets and warning counters. Limits do not disconnect clients automatically.

Limits are applied by the `MOSQ_EVT_MESSAGE_IN` hook. Publishes to `$CONTROL/...`
are processed before that hook, so administrative commands are outside these
quotas. The normal control-topic ACL checks still apply.

Bridge traffic is not exempt from the message hook. A bridge whose username
matches a Dynamic Security account shares that account's quotas. A bridge with
no username can match the anonymous group's roles: all traffic on that bridge
then shares one anonymous connection bucket. Account for this when applying
limits to the anonymous group or to an account used by a bridge.

In the `mosquitto_ctrl` interactive `dynsec` shell:

```text
modifyRole device maxPublishSize 65536
modifyRole device publishRateLimit {"messages":50,"perSeconds":1,"burst":200}
modifyRole device publishRateLimit null
modifyRole device maxPublishSize 0
```

## Commands

### Set default ACL access

Sets the default access behaviour for the different ACL types, assuming there
are no matching ACLs for a topic.

By default, publishClientSend and subscribe default to deny, and
publishClientReceive and unsubscribe default to allow.

Command:
```
{
	"commands":[
		{
			"command": "setDefaultACLAccess",
			"acls":[
				{ "acltype": "publishClientSend", "allow": false },
				{ "acltype": "publishClientReceive", "allow": true },
				{ "acltype": "subscribe", "allow": false },
				{ "acltype": "unsubscribe", "allow": true }
			]
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec setDefaultACLAccess subscribe deny
```

### Get default ACL access

Gets the default access behaviour for the different ACL types.

Command:
```
{
	"commands":[
		{
			"command": "getDefaultACLAccess"
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec getDefaultACLAccess
```

## Create Client

Command:
```
{
	"commands":[
		{
			"command": "createClient",
			"username": "new username",
			"password": "new password",
			"clientid": "", # Optional
			"textname": "", # Optional
			"textdescription": "", # Optional
			"groups": [
				{ "groupname": "group", "priority": 1 }
			], # Optional, groups must exist
			"roles": [
				{ "rolename": "role", "priority": -1 }
			] # Optional, roles must exist
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec createClient username password
```

## Delete Client

Command:
```
{
	"commands":[
		{
			"command": "deleteClient",
			"username": "username to delete"
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec deleteClient username
```

## Enable Client

Command:
```
{
	"commands":[
		{
			"command": "enableClient",
			"username": "username to enable"
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec enableClient username
```

## Disable Client

Stop a client from being able to log in, and kick any clients with matching
username that are currently connected.

Command:
```
{
	"commands":[
		{
			"command": "disableClient",
			"username": "username to disable"
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec disableClient username
```

## Get Client

Command:
```
{
	"commands":[
		{
			"command": "getClient",
			"username": "required username"
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec getClient username
```

## List Clients

Command:
```
{
	"commands":[
		{
			"command": "listClients",
			"verbose": false,
			"count": -1, # -1 for all, or a positive integer for a limited count
			"offset": 0 # Where in the list to start
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec listClients 10 20
```

## Modify Existing Client

Command:
```
{
	"commands":[
		{
			"command": "modifyClient",
			"username": "username to modify"
			"clientid": "new clientid, or empty string to clear", # Optional
			"password": "new password", # Optional
			"textname": "", # Optional
			"textdescription": "", # Optional
			"roles": [
				{ "rolename": "role", "priority": 1 }
			], # Optional
			"groups": [
				{ "groupname": "group", "priority": 1 }
			], # Optional
		}
	]
}
```

Modifying clients isn't currently possible with mosquitto_ctrl.

## Set Client id

Command:
```
{
	"commands":[
		{
			"command": "setClientId",
			"username": "username to change",
			"clientid": "new clientid" # Optional, if blank or missing then client id will be removed.
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec setClientId username clientId
```

## Set Client Password

Command:
```
{
	"commands":[
		{
			"command": "setClientPassword",
			"username": "username to change",
			"password": "new password"
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec setClientPassword username password
```

## Add Client Role

Command:
```
{
	"commands":[
		{
			"command": "addClientRole",
			"username": "client to add role to",
			"rolename": "role to add",
			"priority": -1 # Optional priority
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec addClientRole username rolename
```

## Remove Client Role

Command:
```
{
	"commands":[
		{
			"command": "removeClientRole",
			"username": "client to remove role from",
			"rolename": "role to remove"
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec removeClientRole username rolename
```

## Add Client to a Group

Command:
```
{
	"commands":[
		{
			"command": "addGroupClient",
			"groupname": "group to add client to",
			"username": "client to add to group",
			"priority": -1 # Priority of the group for the client
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec addGroupClient groupname username
```

## Create Group

Command:
```
{
	"commands":[
		{
			"command": "createGroup",
			"groupname": "new group",
			"roles": [
				{ "rolename": "role", "priority": 1 }
			] # Optional, roles must exist

		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec createGroup groupname
```

## Delete Group

Command:
```
{
	"commands":[
		{
			"command": "deleteGroup",
			"groupname: "group to delete"
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec deleteGroup groupname
```

## Get Group

Command:
```
{
	"commands":[
		{
			"command": "getGroup",
			"groupname: "group to get"
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec getGroup groupname
```

## List Groups

Command:
```
{
	"commands":[
		{
			"command": "listGroups",
			"verbose": false,
			"count": -1, # -1 for all, or a positive integer for a limited count
			"offset": 0 # Where in the list to start
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec listGroups
```

## Modify Group

Command:
```
{
	"commands":[
		{
			"command": "modifyGroup",
			"groupname": "group to modify",
			"textname": "", # Optional
			"textdescription": "", # Optional
			"roles": [
				{ "rolename": "role", "priority": 1 }
			], # Optional
			"clients": [
				{ "username": "client", "priority": 1 }
			] # Optional

		}
	]
}
```

Modifying groups isn't currently possible with mosquitto_ctrl.

## Remove Client from a Group

Command:
```
{
	"commands":[
		{
			"command": "removeGroupClient",
			"groupname": "group to remove client from",
			"username": "client to remove from group"
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec removeGroupClient groupname username
```

## Add Group Role

Command:
```
{
	"commands":[
		{
			"command": "addGroupRole",
			"groupname": "group to add role to",
			"rolename": "role to add",
			"priority": -1 # Optional priority
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec addGroupRole groupname rolename
```

## Remove Group Role

Command:
```
{
	"commands":[
		{
			"command": "removeGroupRole",
			"groupname": "group",
			"rolename": "role"
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec removeGroupRole groupname rolename
```

## Set Group for Anonymous Clients

Command:
```
{
	"commands":[
		{
			"command": "setAnonymousGroup",
			"groupname": "group"
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec setAnonymousGroup groupname
```

## Get Group for Anonymous Clients

Command:
```
{
	"commands":[
		{
			"command": "getAnonymousGroup"
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec getAnonymousGroup
```

## Create Role

Command:
```
{
	"commands":[
		{
			"command": "createRole",
			"rolename": "new role",
			"textname": "", # Optional
			"textdescription": "", # Optional
			"acls": [
				{ "acltype": "subscribePattern", "topic": "topic/#", "priority": -1, "allow": true}
			] # Optional
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec createRole rolename
```

## Get Role

Command:
```
{
	"commands":[
		{
			"command": "getRole",
			"rolename": "role",
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec getRole rolename
```

## List Roles

Command:
```
{
	"commands":[
		{
			"command": "listRoles",
			"verbose": false,
			"count": -1, # -1 for all, or a positive integer for a limited count
			"offset": 0 # Where in the list to start
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec listRoles
```

## Modify Role

Command:
```
{
	"commands":[
		{
			"command": "modifyRole",
			"rolename": "role to modify"
			"textname": "", # Optional
			"textdescription": "", # Optional
			"acls": [
				{ "acltype": "subscribePattern", "topic": "topic/#", "priority": -1, "allow": true }
			] # Optional
		}
	]
}
```

Modifying roles isn't currently possible with mosquitto_ctrl.

## Delete Role

Command:
```
{
	"commands":[
		{
			"command": "deleteRole",
			"rolename": "role"
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec deleteRole rolename
```

## Add Role ACL

Command:
```
{
	"commands":[
		{
			"command": "addRoleACL",
			"rolename": "role",
			"acltype": "subscribePattern",
			"topic": "topic/#",
			"priority": -1,
			"allow": true
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec addRoleACL rolename subscribeLiteral topic/# deny
```

## Remove Role ACL

Command:
```
{
	"commands":[
		{
			"command": "removeRoleACL",
			"rolename": "role",
			"acltype": "subscribePattern",
			"topic": "topic/#"
		}
	]
}
```

mosquitto_ctrl example:
```
mosquitto_ctrl dynsec removeRoleACL rolename subscribeLiteral topic/#
```
