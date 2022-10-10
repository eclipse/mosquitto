<!--
.. title: Version 1.5.4 released
.. slug: version-154-released
.. date: 2018-11-08 15:00:26 UTC+00:00
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

This is a bugfix and security release.

# Version 1.5.4 changes

## Security
- When using a TLS enabled websockets listener with `require_certificate`
  enabled, the mosquitto broker does not correctly verify client certificates.
  This is now fixed. All other security measures operate as expected, and in
  particular non-websockets listeners are not affected by this. Closes [#996].

## Broker
- Process all pending messages even when a client has disconnected. This means
  a client that send a PUBLISH then DISCONNECT quickly, then disconnects will
  have its DISCONNECT message processed properly and so no Will will be sent.
  Closes [#7].
- $SYS/broker/clients/disconnected should never be negative. Closes [#287].
- Give better error message if a client sends a password without a username.
  Closes [#1015].
- Fix bridge not honoring `restart_timeout`. Closes [#1019].
- Don't disconnect a client if an auth plugin denies access to SUBSCRIBE.
  Closes [#1016].

## Library
- Fix memory leak that occurred if `mosquitto_reconnect()` was used when TLS
  errors were present. Closes [#592].
- Fix TLS connections when using an external event loop with
  `mosquitto_loop_read()` and `mosquitto_write()`. Closes [#990].

## Build
- Fix clients not being compiled with threading support when using CMake.
  Closes [#983].
- Header fixes for FreeBSD. Closes [#977].
- Use `_GNU_SOURCE` to fix build errors in websockets and getaddrinfo usage.
  Closes [#862] and [#933].
- Fix builds on QNX 7.0.0. Closes [#1018].

[#7]: https://github.com/eclipse/mosquitto/issues/7
[#287]: https://github.com/eclipse/mosquitto/issues/287
[#592]: https://github.com/eclipse/mosquitto/issues/592
[#933]: https://github.com/eclipse/mosquitto/issues/933
[#977]: https://github.com/eclipse/mosquitto/issues/977
[#983]: https://github.com/eclipse/mosquitto/issues/983
[#990]: https://github.com/eclipse/mosquitto/issues/990
[#996]: https://github.com/eclipse/mosquitto/issues/996
[#1015]: https://github.com/eclipse/mosquitto/issues/1015
[#1016]: https://github.com/eclipse/mosquitto/issues/1016
[#1018]: https://github.com/eclipse/mosquitto/issues/1018
[#1019]: https://github.com/eclipse/mosquitto/issues/1019
