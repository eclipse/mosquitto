# Plugins

This directory contains plugins for use with Mosquitto.

## Dynamic security
This is a fully functioning plugin that implements authentication and access
control, with configuration via a $CONTROL topic. See the readme in
dynamic-security for more information.

## Examples / Add properties
This is an **example** plugin that demonstrates adding MQTT v5 properties to
messages, and how to get client information.

## Examples / Authenticate by IP address
This is an **example** plugin that demonstrates a basic authentication callback
that allows clients based on their IP address. Password based authentication is
preferred over this very simple type of access control.

## Examples / Client lifetime stats
This is an **example** plugin that collects counts of how long client sessions
last, in different time buckets of 0, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1k,
2k, 5k, 10k, 20k, 50k, 100k, 200k, 500k, 1M, 2M, 5M, 10M, 20M, 50M, 100M, 200M,
500M seconds. It periodically publishes the counts at
`$SYS/broker/client/lifetimes/<bucket>`.

## Examples / Client properties
This is an **example** plugin that demonstrates some of the functions for
retrieving client information such as client id and username.

## Examples / Connection state
This is an **example** plugin to demonstrate the use of the connect and
disconnect events. It publishes messages to
$SYS/broker/connection/client/<client id>/state for every client that connects
to the broker, to indicate the connection state of that client.

## Examples / Deferred authentication
This is an **example** plugin to demonstrate how a plugin can carry out
delayed basic authentication. This method should be used where the plugin
sends an authentication request to an external server so that if there is a
delay in getting a response it does not block the broker. The plugin may spawn
extra threads to handle the authentication requests, but the call to
`mosquitto_complete_basic_auth()` must happen in the main Mosquitto thread.

## Examples / Message timestamp
This is an **example** plugin to demonstrate how it is possible to attach MQTT
v5 properties to messages after they have been received, and before they are
sent on to subscribers.

This plugin attaches a user-property property to each message which contains
the ISO-8601 timestamp of the time the message was received by the broker. This
means it is possible for MQTT v5 clients to see how old a retained message is,
for example.

## Examples / Payload modification
This is an **example** plugin to demonstrate how it is possible to modify the
payload of messages after they have been received, and before they are sent on
to subscribers.

If you are considering using this feature, you should be very certain you have
verified the payload is the correct format before modifying it.

This plugin adds the text string "hello " to the beginning of each payload, so
with anything other than simple plain text messages it will corrupt the payload
contents.

## Examples / Payload size stats
This is an **example** plugin that collects counts of payload message sizes, in
time buckets of 0, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1k, 2k, 5k, 10k, 20k,
50k, 100k, 200k, 500k, 1M, 2M, 5M, 10M, 20M, 50M, 100M, 200M, 500M bytes. It
periodically publishes the counts at `$SYS/broker/publish/sizes/<bucket>`.

## Examples / Print IP on publish
This is an **example** plugin that prints out client ID and IP address of any
client that publishes on a particular topic.

## Examples / Topic modification
This is an **example** plugin to demonstrate how it is possible to modify the
topic of messages after they have been received, and before they are sent on
to subscribers.

This plugin removes the `/uplink` end part of topics that match the pattern
`device/+/data/uplink`, so devices publishing to `device/0001/data/uplink` will
effectively be publishing to `device/0001/data`.

## Examples / Wildcard temp
This is an **example** plugin that denies access to the `#` subscription topic
only. This prevents clients from discovering which topics are active and
reduces outgoing bandwidth. If clients connect with username `wildcard` and
subscribes to `#` they will be allowed 20 seconds of access, after which the
subscription will be silently removed.
