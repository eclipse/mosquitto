<!--
.. title: Version 1.6.4 released
.. slug: version-1-6-4-released
.. date: 2019-08-01 18:00:00 UTC+1
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

This is a bugfix release.

## Broker
- Fix persistent clients being incorrectly expired on Raspberry Pis.
  Closes [#1272].
- Windows: Allow other applications access to the log file when running.
  Closes [#515].
- Fix incoming QoS 2 messages being blocked when `max_inflight_messages` was
  set to 1. Closes [#1332].
- Fix incoming messages not being removed for a client if the topic being
  published to does not have any subscribers. Closes [#1322].

## Client library
- Fix MQTT v5 subscription options being incorrectly set for MQTT v3
  subscriptions. Closes [#1353].
- Make behaviour of `mosquitto_connect_async()` consistent with
  `mosquitto_connect()` when connecting to a non-existent server.
  Closes [#1345].
- `mosquitto_string_option(mosq, MOSQ_OPT_TLS_KEYFORM, ...)` was incorrectly
  returning `MOSQ_ERR_INVAL` with valid input. This has been fixed.
  Closes [#1360].
- `on_connect` callback is now called with the correct v5 reason code if a v5
  client connects to a v3.x broker and is sent a CONNACK with the
  "unacceptable protocol version" connack reason code.
- Fix memory leak when setting v5 properties in `mosquitto_connect_v5()`.
- Fix properties not being sent on QoS>0 PUBLISH messages.

## Clients
- `mosquitto_pub`: fix error codes not being returned when `mosquitto_pub` exits.
  Closes [#1354].
- All clients: improve error messages when connecting to a v3.x broker when in
  v5 mode. Closes [#1344].

## Other
- Various documentation fixes.

[#515]: https://github.com/eclipse-mosquitto/mosquitto/issues/515
[#1272]: https://github.com/eclipse-mosquitto/mosquitto/issues/1272
[#1322]: https://github.com/eclipse-mosquitto/mosquitto/issues/1322
[#1332]: https://github.com/eclipse-mosquitto/mosquitto/issues/1332
[#1344]: https://github.com/eclipse-mosquitto/mosquitto/issues/1344
[#1345]: https://github.com/eclipse-mosquitto/mosquitto/issues/1345
[#1353]: https://github.com/eclipse-mosquitto/mosquitto/issues/1353
[#1354]: https://github.com/eclipse-mosquitto/mosquitto/issues/1354
[#1360]: https://github.com/eclipse-mosquitto/mosquitto/issues/1360
