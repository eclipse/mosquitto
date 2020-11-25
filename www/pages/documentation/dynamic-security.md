<!--
.. title: Dynamic Security Plugin
.. slug: dynamic-security
.. date: 2020-11-15 09:25:28 UTC
.. tags:
.. category:
.. link:
.. description:
.. type: text
-->

## Introduction

The Dynamic Security plugin is a Mosquitto plugin which provides role based
authentication and access control features that can updated whilst the broker
is running, using a special topic based API.

It is supported since Mosquitto 2.0, and should be available in all
installations, but will not be activated by default.

## Concepts

This section describes the concepts of how the plugin operates. If you want to
find out how to use the plugin features, look in the [Usage] section below.

The plugin allows you to create three main objects, `clients`, `groups`, and `roles`.

This document will use the term `clients` to mean the clients defined in the
plugin, and `devices` or `users` to mean the MQTT clients that connect to the
broker.

---

### Clients

When you want a device or user to be able to connect and authenticate to the
broker, you create a client. Each client has the following attributes:

#### Username

The client username maps to the username provided in the CONNECT packet when a
device connects. The username is unique across the plugin, so attempting to
create a client with a duplicate username will result in an error. The username
acts as the primary key if you want to change anything about the client.

#### Password

The client password maps to the password provided in the CONNECT packet when a
device connects. The password may be unset when a client is created, this will
mean that devices will be unable to connect as the corresponding client.

The password can be updated at any point, but only by a client with the correct
access. Devices typically cannot update their own passwords.

#### Client ID

The client id maps to the client id provided in the CONNECT packet when a
device connects. This is an optional attribute.

If the client id is empty or not provided, then any device can connect with the
username for this client regardless of its client id. This means that multiple
devices could connect with the same credentials at the same time, but sharing
credentials between devices is not recommended.

If the client id is set, then a device can only connect as this client if the
triple of username, password, and client id all match those in the client.

#### Groups

A client can be a member of any number of groups.

#### Roles

A client can be assigned to any number of roles. A role gives the client access
to different topics.

#### Text name

This is an optional text field to give a human friendly name to this client.

#### Text description

This is an optional text field to give a human friendly description to this
client.

#### Disabled

A client can be set to be enabled/disabled at any point. Disabling a client
means that any devices currently connected using the credentials for that
client will be disconnected and unable to reconnect.

---

### Groups

Multiple clients can be placed in a group. Groups can have roles assigned to
them, so using groups is appropriate where you have a number of clients that
need to have the same access.

Groups have the following attributes:

#### Group name

The group name is the primary name for the group. It is used when modifying the
group in any way, such as adding a client or a role.

#### Roles

A group can be assigned to any number of roles. A role gives the group access
to different topics.

#### Text name

This is an optional text field to give a human friendly name to this group.

#### Text description

This is an optional text field to give a human friendly description to this
group.

---

### Roles

Roles contain multiple access control lists (ACLs), and can be assigned to clients and/or groups.

Roles have the following attributes:

#### Role name

The role name is the primary name for the role. It is used when modifying the
role in any way, such as adding an ACL.

#### Access Control Lists

ACLs are the feature which allows access to topics to be controlled. Checks are
made on different events as they happen: `publishClientSend`,
`publishClientReceive`, `subscribe`, and `unsubscribe`. The `publishClientSend`
event occurs when a device sends a PUBLISH message to the broker, i.e. "is the
device allowed to publish to this topic". The `publishClientReceive` event
occurs when a device is due to receive a PUBLISH message from the broker, i.e.
it has a valid subscription and a matching message has been published to the
broker. The `subscribe` event occurs in response to a device sending a
SUBSCRIBE message, and the `unsubscribe` event occurs in response to a device
sending an UNSUBSCRIBE packet.

The default behaviour of the different events can be set to allow or deny
access. The default behaviour applies if no matching ACL is found.

The default behaviour for the different events when the plugin has first been
configured is:

* `publishClientSend`: deny
* `publishClientReceive`: allow
* `subscribe`: deny
* `unsubscribe`: allow

There is some overlap between `publishClientReceive` and `subscribe`. In most
cases, using a `subscribe` ACL is sufficient to provide the control you need,
however by combining the two types it is possible to e.g. allow subscriptions
to a wildcard topic like `topic/#`, but deny access for device to receive
messages on a specific topic within that hierarchy like 'topic/secret'.

The different events have ACL types associated with them, and it is these ACLs
that you will add to your roles. Each ACL has a `topic`, a `priority`, and can
be set to `allow` or `deny`. 

The `publishClientSend` and `publishClientReceive` ACL types map directly to
the events of the same name. The topic can contain wildcards, so allowing send
access to `topic/#` will allow devices to publish to all topics in the
`topic/#` hierarchy, including `topic`.

The `subscribe` and `unsubscribe` events have two ACL types each:
`subscribeLiteral`, `subscribePattern`, `unsubscribeLiteral`, and
`unsubscribePattern`.

The `*Literal` ACL types make a literal comparison between the topic filter
provided for the ACL and the topic filter provided in the SUBSCRIBE or
UNSUBSCRIBE message. This means that setting a `subscribeLiteral` ACL with
topic filter `#` to deny would prevent matching devices from subscribing the
the `#` topic filter only, but still allow them to subscribe to `topic/#`, for
example.

The `*Pattern` ACL types allow or deny access based on a wildcard comparison of
the ACL topic filter and the topic provided in the SUBSCRIBE or UNSUBSCRIBE
message. This means that setting a `subscribePattern` ACL with topic filter `#`
to deny would prevent matching devices from subscribing to any topic at all.

#### Text name

This is an optional text field to give a human friendly name to this role.

#### Text description

This is an optional text field to give a human friendly description to this
role.

---

### Priorities

**FIXME** example needs completing.

If you are working with more than one role per client or group, or more than
one group per client, then it is crucial to understand how roles and ACLs are
applied.

The order in which checks are made is determined in part by the `priority` of
groups, roles and ACLs. Each client group has a priority, each client role and
group role has a priority, and each ACL within a role has a priority. If not
set explicitly, priorities will default to -1.

For each of the group, role, and ACL objects, checks are made in priority order
from the highest numerical value to the lowest numerical value. If two objects
of the same type have the same priority, then they will be checked in
lexographical order according to the username/groupname/rolename, but it is
advised to use unique priorities per object type.

When an event occurs that needs an ACL check, the ACLs for that ACL type are
checked in order until there is a matching ACL for the topic in question.

Within each role that is checked, the ACLs are checked in priority order.

The roles assigned to a client are checked first, in priority order.
Each client group is checked in priority order, with all of the roles in a
group being checked in priority order before the next group is checked.

As an example, let us assume we have the following client, groups, and roles:

Client: `sensor`
Groups: `temperature` (priority 2), `humidity` (priority 1)
Roles: `hallway`

Group: `temperature`
Roles: `input` (priority 5), `output` (priority 1)

Group: `humidity`
Roles: `humidity`

Role: `hallway`

Role: `input`

Role: `output`

Role: `humidity`


### Anonymous access

All of the documentation so far assumes that you do not allow anonymous
unauthenticated access - meaning devices or users that connect without a
username.

You may wish to allow anonymous access, but still make use of the dynamic
security plugin, and this is supported through the automatic anonymous group.
If allowed, anything connecting without a username will be assigned to a group
that you define. By assigning roles to that group, you can control what
anonymous devices can access.

## Initial configuration

To use the Dynamic Security plugin, it must be configured in the broker and an
initial plugin configuration must be generated.

To configure the broker, add the following to your configuration file.

Linux/BSD:
```
plugin path/to/mosquitto_dynamic_security.so
plugin_opt_config_file path/to/dynamic-security.json
```

Windows:
```
plugin path\to\mosquitto_dynamic_security.dll
plugin_opt_config_file path\to\dynamic-security.json
```

It is recommended to use `per_listener_settings false` with this plugin, so all
listeners use the same authentication and access control.

The `dynamic-security.json` file is where the plugin configuration will be
stored. To generate an initial file, use the `mosquitto_ctrl` utility.

```
mosquitto_ctrl dynsec init path/to/dynamic-security.json admin-user
```

Choose your own `admin-user` username. You will be asked for a password for the
client. This user will be assigned the `admin` role, which has the following
access:

* publishClientSend: `$CONTROL/dynamic-security/#` - this allows the client to
  control the Dynamic security plugin.
* publishClientReceive: `$CONTROL/dynamic-security/#` - this allows the client
  to receive information from the plugin. This is not necessary in the default
  configuration, but is included in case the default behaviour for
  `publishClientReceive` is set to `deny`.
* subscribePattern: `$CONTROL/dynamic-security/#` - this allows the client to
  receive information from the plugin.
* publishClientReceive: `$SYS/#` - this allows the client to see the broker
  metrics.
* subscribePattern: `$SYS/#` - this allows the client to see the broker
  metrics.
* publishClientReceive: `#` - this allows the client to examine the messages
  being published by other clients.
* subscribePattern: `#` - this allows the client to examine the messages
  being published by other clients.
* unsubscribePattern: `#` - this allows the client to undo previous
  subscriptions. This is not necessary in the default configuration, but is
  included in case the default behaviour for `unsubscribe` is set to `deny`.

The admin user does not have access to publish to normal application topics in
the `#` hierarchy by default. You are strongly encouraged to keep the admin
user purely for administering the plugin, and create other clients for your
application.

## Using mosquitto_ctrl with a running broker

The initial configuration is the only time that `mosquitto_ctrl` does not
connect to a broker to carry out the configuration. All other commands require
a connection to a broker, and hence a username, password, and whatever else is
required for that particular connection.

The connection options must be given before the `dynsec` part of the command
line:
```
mosquitto_ctrl <connection options> dynsec <command> ...
```

For example:

```
mosquitto_ctrl -u admin -h localhost dynsec <command> ...
```

It is possible to provide the admin password on the command line, but this is
not recommended.

See **FIXME** for the full list of options available for `mosquitto_ctrl`.

## Configuring default access

The initial configuration sets the default ACL type behaviours to:

* `publishClientSend`: deny
* `publishClientReceive`: allow
* `subscribe`: deny
* `unsubscribe`: allow

If you wish to change these, use `mosquitto_ctrl`. 

```
mosquitto_ctrl <options> dynsec setDefaultACLAccess publishClientSend deny
mosquitto_ctrl <options> dynsec setDefaultACLAccess publishClientReceive deny
mosquitto_ctrl <options> dynsec setDefaultACLAccess subscribe deny
mosquitto_ctrl <options> dynsec setDefaultACLAccess unsubscribe deny
```

You can examine the current default access with the `getDefaultACLAccess` command:

```
mosquitto_ctrl <options> dynsec getDefaultACLAccess unsubscribe
```

## Creating and modifying clients

To create a new client:

```
mosquitto_ctrl <options> dynsec createClient <username>
```

This creates a client which does not have a client id associated with it. You
will be asked for the password for the new client before you are asked for the
admin user password. Pay attention to the messages on the command line.

```
mosquitto_ctrl <options> dynsec createClient <username> -i <client id>
```
This creates a client which has a client id associated with it.


To delete a client (clients connected with these credentials will be
disconnected from the broker):

```
mosquitto_ctrl <options> dynsec deleteClient <username>
```

To disable a client (clients connected with these credentials will be
disconnected from the broker):

```
mosquitto_ctrl <options> dynsec disableClient <username>
```

To enable a client (clients will be able to use these credentials to log in
again):

```
mosquitto_ctrl <options> dynsec enableClient <username>
```

To set a client password:

```
mosquitto_ctrl <options> dynsec setClientPassword <username>
mosquitto_ctrl <options> dynsec setClientPassword <username> <password>
```

To add/remove a role to/from a client:

```
mosquitto_ctrl <options> dynsec addClientRole <username> <rolename> <priority>
mosquitto_ctrl <options> dynsec removeClientRole <username> <rolename>
```

To get information on a client:

```
mosquitto_ctrl <options> dynsec getClient <username>
```

To list all clients:

```
mosquitto_ctrl <options> dynsec listClients
```

The `modifyClient` command also exists in the topic API, but is not currently available in `mosquitto_ctrl`.


## Creating and modifying groups

To create a new group:

```
mosquitto_ctrl <options> dynsec createGroup <groupname>
```

To delete a group:

```
mosquitto_ctrl <options> dynsec deleteGroup <groupname>
```

To add/remove a client to/from a group:

```
mosquitto_ctrl <options> dynsec addGroupClient <groupname> <username> <priority>
mosquitto_ctrl <options> dynsec removeGroupClient <groupname> <username>
```

In this case the `priority` refers to the priority of the group within the
client's list of groups.

To add/remove a role to/from a group:

```
mosquitto_ctrl <options> dynsec addGroupRole <groupname> <rolename> <priority>
mosquitto_ctrl <options> dynsec removeGroupRole <groupname> <rolename>
```

To set/get the group that anonymous devices are assigned to:

```
mosquitto_ctrl <options> dynsec setAnonymousGroup <groupname>
mosquitto_ctrl <options> dynsec getAnonymousGroup
```

To get information on a group:

```
mosquitto_ctrl <options> dynsec getGroup <groupname>
```

To list all groups:

```
mosquitto_ctrl <options> dynsec listGroups
```

The `modifyGroup` command also exists in the topic API, but is not currently
available in `mosquitto_ctrl`.

## Creating and modifying roles

To create a new role:

```
mosquitto_ctrl <options> dynsec createRole <rolename>
```

To delete a role:

```
mosquitto_ctrl <options> dynsec deleteRole <rolename>
```

To add an ACL to a role:
```
mosquitto_ctrl <options> dynsec addRoleACL <rolename> <acltype> <topic filter> allow|deny <priority>
```
Where `acltype` is one of `publishClientSend`, `publishClientReceive`,
`subscribeLiteral`, `subscribePattern`, `unsubscribeLiteral`, and
`unsubscribePattern`.

For example:

```
mosquitto_ctrl <options> dynsec addRoleACL <rolename> clientPublishSend client/topic allow 5
```

To remove an ACL from a role using the topic filter as the key:
```
mosquitto_ctrl <options> dynsec removeRoleACL <rolename> <acltype> <topic filter>
```
For example:

```
mosquitto_ctrl <options> dynsec removeRoleACL <rolename> clientPublishSend client/topic
```

To get information on a role:

```
mosquitto_ctrl <options> dynsec getRole <rolename>
```

To list all roles:

```
mosquitto_ctrl <options> dynsec listRoles
```

The `modifyRole` command also exists in the topic API, but is not currently
available in `mosquitto_ctrl`.
