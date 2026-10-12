<!--
.. title: Version 1.6.2 released
.. slug: version-1-6-2-released
.. date: 2019-04-30 13:07:00 UTC+1
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

This is a security and bugfix release.

## Security

If a client connects using MQTT v5, will a Will message that has MQTT v5
properties attached, and the very first Will property is one of `content-type`,
`correlation-data`, `payload-format-indicator`, or `response-topic`, then at
the point the client disconnects, the broker will attempt to read from freed
memory, resulting in a possible crash.


## Broker
- Fix memory access after free, leading to possible crash, when v5 client with
  Will message disconnects, where the Will message has as its first property
  one of `content-type`, `correlation-data`, `payload-format-indicator`, or
  `response-topic`.  Closes [#1244].
- Fix build for `WITH_TLS=no`. Closes [#1250].
- Fix Will message not allowing `user-property` properties.
- Fix broker originated messages (e.g. `$SYS/broker/version`) not being
  published when `check_retain_source` set to true. Closes [#1245].
- Fix `$SYS/broker/version` being incorrectly expired after 60 seconds.
  Closes [#1245].

## Library
- Fix crash after client has been unable to connect to a broker. This occurs
  when the client is exiting and is part of the final library cleanup routine.
  Closes [#1246].

## Clients
- Fix `-L` url parsing. Closes [#1248].

[#1244]: https://github.com/eclipse-mosquitto/mosquitto/issues/1244
[#1245]: https://github.com/eclipse-mosquitto/mosquitto/issues/1245
[#1246]: https://github.com/eclipse-mosquitto/mosquitto/issues/1246
[#1250]: https://github.com/eclipse-mosquitto/mosquitto/issues/1250
