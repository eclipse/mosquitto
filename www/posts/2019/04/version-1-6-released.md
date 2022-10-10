<!--
.. title: Version 1.6 released
.. slug: version-1-6-released
.. date: 2019-04-17 22:08:00 UTC+1
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

This is a feature release and represents a substantial amount of change in the
project. Since version 1.5, the overall code line count for the broker, library
and clients has increased by 37% to 28k. Testing has been an important focus
for this release. The number of tests has increased from 102 to 412. The test
coverage, whilst still needing further improvement, has increased from 56% to
61%.

A summary of the notable features is given below.

# MQTT v5 support

The big addition for this release is support for MQTT v5. This covers the
broker, client library and client, and gives full support for the new
specification, although not all features are accessible as they will be.

You can quickly test out a v5 client by using `-V 5` and adding properties with
the `-D` option, for example:

```
mosquitto_sub -V 5 -D connect receive-maximum 3 -D subscribe subscription-identifier 1 ...
```

The authentication plugin interface has been extended to allow use of the v5
extended authentication feature.

# Performance improvements

A number of performance improvements have been implemented in the broker,
including the message routing logic, topic matching, and persistence file
reading/writing.

More improvements are planned for the next release.

# New client - mosquitto_rr

`mosquitto_rr` is the "request-response" client, intended for the situation
where you want to publish a request message and await a response. It works best
with the MQTT v5 request-response features, but can be used with v3.1.1 servers
if the client it is talking to knows how to respond. This tool is almost
certainly not going to see as much use as `mosquitto_sub` or `mosquitto_pub`,
but is a useful utility to have available.

# Contributed features

Some notable features have been contributed by the community.

On the TLS front, support for ALPN allows bridges and clients to connect to
servers that have multiple protocols on a single port. The new OCSP stapling
support allows the status of TLS certificates to be validated. Finally, TLS
Engine support has been added.

Away from TLS, support for Automotive DLT logging has been added, disabled by
default.

# Deprecations

The C++ wrapper library, libmosquittopp is now deprecated and will be removed
in version 2.0. It remains largely unchanged since v1.5.

The C library, libmosquitto, is having its interface changed for version 2.0,
so any current function should be considered at risk. The rationale for this is
to consolidate the changes introduced since version 1.0, in particular the
large number of functions required to support MQTT v5, but that otherwise
closely match existing functions.

Support for TLS v1.0 has been dropped. Support for TLS v1.1 will be dropped in
version 2.0.

# Changelog

The more detailed changelog is below, but does not include many of the
fixes and improvements that have been made:

## Broker features
- Add support for MQTT v5
- Add support for OCSP stapling.
- Add support for ALPN on bridge TLS connections. Closes [#924].
- Add support for Automotive DLT logging.
- Add TLS Engine support.
- Persistence file read/write performance improvements.
- General performance improvements.
- Add `max_keepalive option`, to allow a maximum keepalive value to be set for
  MQTT v5 clients only.
- Add `bind_interface` option which allows a listener to be bound to a
  specific network interface, in a similar fashion to the `bind_address` option.
  Linux only.
- Add improved bridge restart interval based on Decorrelated Jitter.
- Add `dhparamfile` option, to allow DH parameters to be loaded for Ephemeral
  DH support
- Disallow writing to $ topics where appropriate.
- Add explicit support for TLS v1.3.
- Drop support for TLS v1.0.
- Improved general support for broker generated client ids. Removed libuuid
  dependency.
- `auto_id_prefix` now defaults to 'auto-'.
- QoS 1 and 2 flow control improvements.

## Client library features
- Add support for MQTT v5
- Add `mosquitto_subscribe_multiple()` for sending subscriptions to multiple
  topics in one command.
- Add TLS Engine support.
- Add explicit support for TLS v1.3.
- Drop support for TLS v1.0.
- QoS 1 and 2 flow control improvements.

## Client features
- Add support for MQTT v5
- Add `mosquitto_rr ` client, which can be used for "request-response" messaging,
  by sending a request message and awaiting a response.
- Add TLS Engine support.
- Add support for ALPN on TLS connections. Closes [#924].
- Add `-D ` option for all clients to specify MQTT v5 properties.
- Add `-E ` to `mosquitto_sub `, which causes it to exit immediately after having
  its subscriptions acknowledged. Use with `-c` to create a durable client
  session without requiring a message to be received.
- Add `--remove-retained` to `mosquitto_sub`, which can be used to clear retained
  messages on a broker.
- Add `--repeat` and `--repeat-delay` to `mosquitto_pub`, which can be used to
  repeat single message publishes at a regular interval.
- -V now accepts `5`, `311`, `31`, as well as `mqttv5` etc.
- Add explicit support for TLS v1.3.
- Drop support for TLS v1.0.

## Broker fixes
- Improve error reporting when creating listeners.
- Fix `mosquitto_passwd` crashing on corrupt password file. Closes [#1207].
- Fix build on SmartOS due to missing IPV6_V6ONLY. Closes [#1212].

## Client library fixes
- Add missing `mosquitto_userdata()` function.

## Client fixes
- `mosquitto_pub` wouldn't always publish all messages when using `-l` and
  QoS>0. This has been fixed.
- `mosquitto_sub` was incorrectly encoding special characters when using %j
  output format. Closes [#1220].


[#924]: https://github.com/eclipse/mosquitto/issues/924
[#1208]: https://github.com/eclipse/mosquitto/issues/1208
[#1212]: https://github.com/eclipse/mosquitto/issues/1212
[#1220]: https://github.com/eclipse/mosquitto/issues/1220
