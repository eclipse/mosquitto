<!--
.. title: Version 1.6.3 released
.. slug: version-1-6-3-released
.. date: 2019-06-18 13:00:00 UTC+1
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

This is a bugfix release.

## Broker
- Fix detection of incoming v3.1/v3.1.1 bridges. Closes [#1263].
- Fix default `max_topic_alias` listener config not being copied to the in-use
  listener when compiled without TLS support.
- Fix random number generation if compiling using `WITH_TLS=no` and on Linux
  with glibc >= 2.25. Without this fix, no random numbers would be generated
  for e.g. on broker client id generation, and so clients connecting expecting
  this feature would be unable to connect.
- Fix compilation problem related to `getrandom()` on non-glibc systems.
- Fix Will message for a persistent client incorrectly being sent when the
  client reconnects after a clean disconnect. Closes [#1273].
- Fix Will message for a persistent client not being sent on disconnect.
  Closes [#1273].
- Improve documentation around the upgrading of persistence files. Closes
  [#1276].
- Add 'extern "C"' on mosquitto_broker.h and mosquitto_plugin.h for C++ plugin
  writing. Closes [#1290].
- Fix persistent Websockets clients not receiving messages after they
  reconnect, having sent DISCONNECT on a previous session. Closes [#1227].
- Disable TLS renegotiation. Client initiated renegotiation is considered to
  be a potential attack vector against servers. Closes [#1257].
- Fix incorrect shared subscription topic '$shared'.
- Fix zero length client ids being rejected for MQTT v5 clients with clean
  start set to true.
- Fix MQTT v5 overlapping subscription behaviour. Clients now receive message
  from all matching subscriptions rather than the first one encountered, which
  ensures the maximum QoS requirement is met.
- Fix incoming/outgoing quota problems for QoS>0.
- Remove obsolete `store_clean_interval` from documentation.

## Client library
- Fix typo causing build error on Windows when building without TLS support.
  Closes [#1264].

## Clients
- Fix -L url parsing when `/topic` part is missing.
- Stop some error messages being printed even when `--quiet` was used.
  Closes [#1284].
- Fix `mosquitto_pub` exiting with error code 0 when an error occurred.
  Closes [#1285].
- Fix `mosquitto_pub` not using the `-c` option. Closes [#1273].
- Fix MQTT v5 clients not being able to specify a password without a username.
  Closes [#1274].
- Fix `mosquitto_pub -l` not handling network failures. Closes [#1152].
- Fix `mosquitto_pub -l` not handling zero length input. Closes [#1302].
- Fix double free on exit in `mosquitto_pub`. Closes [#1280].

## Documentation:
- Remove references to Python binding and C++ wrapper in libmosquitto man
  page. Closes [#1266].

## Build
- CLIENT_LDFLAGS now uses LDFLAGS. Closes [#1294].

[#1152]: https://github.com/eclipse-mosquitto/mosquitto/issues/1152
[#1227]: https://github.com/eclipse-mosquitto/mosquitto/issues/1227
[#1257]: https://github.com/eclipse-mosquitto/mosquitto/issues/1257
[#1263]: https://github.com/eclipse-mosquitto/mosquitto/issues/1263
[#1264]: https://github.com/eclipse-mosquitto/mosquitto/issues/1264
[#1266]: https://github.com/eclipse-mosquitto/mosquitto/issues/1266
[#1273]: https://github.com/eclipse-mosquitto/mosquitto/issues/1273
[#1273]: https://github.com/eclipse-mosquitto/mosquitto/issues/1273
[#1273]: https://github.com/eclipse-mosquitto/mosquitto/issues/1273
[#1274]: https://github.com/eclipse-mosquitto/mosquitto/issues/1274
[#1276]: https://github.com/eclipse-mosquitto/mosquitto/issues/1276
[#1280]: https://github.com/eclipse-mosquitto/mosquitto/issues/1280
[#1284]: https://github.com/eclipse-mosquitto/mosquitto/issues/1284
[#1285]: https://github.com/eclipse-mosquitto/mosquitto/issues/1285
[#1290]: https://github.com/eclipse-mosquitto/mosquitto/issues/1290
[#1294]: https://github.com/eclipse-mosquitto/mosquitto/issues/1294
[#1302]: https://github.com/eclipse-mosquitto/mosquitto/issues/1302
