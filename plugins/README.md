# Plugins

This directory contains plugins for use with Mosquitto.

## Dynamic security
This is a fully functioning plugin that implements authentication and access
control, with configuration via a $CONTROL topic. See the readme in
dynamic-security for more information.

## Message timestamp
This is an **example** plugin to demonstrate how it is possible to attach MQTT v5 properties to messages after they have been received, and before they are sent on to subscribers.

This plugin attaches a user-property property to each message which contains the ISO-8601 timestamp of the time the message was received by the broker. This means it is possible for MQTT v5 clients to see how old a retained message is, for example.

## Payload modification
This is an **example** plugin to demonstrate how it is possible to modify the payload of messages after they have been received, and before they are sent on to subscribers.

If you are considering using this feature, you should be very certain you have verified the payload is the correct format before modifying it.

This plugin adds the text string "hello " to the beginning of each payload, so with anything other than simple plain text messages it will corrupt the payload contents.
