<!--
.. title: Version 1.6.5 released
.. slug: version-1-6-5-released
.. date: 2019-09-12 15:00:00 UTC+1
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

This is a bugfix release.

# Compatibility
- The most recent version of libwebsockets (3.2.0) changed its behaviour and is
  not compatible with Mosquitto. This has been fixed for the next libwebsockets
  release. The 1.6.5 release refuses to compile with libwebsockets 3.2.0. All
  previous versions of Mosquitto that use websockets are affected by the change
  in behaviour.

# Broker
- Fix v5 DISCONNECT packets with remaining length == 2 being treated as a
  protocol error. Closes [#1367].
- Fix support for libwebsockets 3.x (excluding 3.2.0)
- Fix slow websockets performance when sending large messages. Closes [#1390].
- Fix bridges potentially not connecting on Windows. Closes [#478].
- Fix clients authorised using `use_identity_as_username` or
  `use_subject_as_username` being disconnected on SIGHUP. Closes [#1402].
- Improve error messages in some situations when clients disconnect. Reduces
  the number of "Socket error on client X, disconnecting" messages.
- Fix Will for v5 clients not being sent if will delay interval was greater
  than the session expiry interval. Closes [#1401].
- Fix CRL file not being reloaded on HUP. Closes [#35].
- Fix repeated "Error in poll" messages on Windows when only websockets
  listeners are defined. Closes [#1391].

# Client library
- Fix reconnect backoff for the situation where connections are dropped rather
  than refused. Closes [#737].
- Fix missing locks on `mosq->state`. Closes [#1374].

# Documentation
- Improve details on global/per listener options in the mosquitto.conf man page.
  Closes [#274].
- Clarify behaviour when clients exceed the `message_size_limit`. Closes [#448].
- Improve documentation for `max_inflight_bytes`, `max_inflight_messages`,
  and `max_queued_messages`.

# Build
- Fix missing function warnings on NetBSD.
- Fix `WITH_STATIC_LIBRARIES` using CMake on Windows. Closes [#1369].
- Guard `ssize_t` definition on Windows. Closes [#522].


[#35]: https://github.com/eclipse-mosquitto/mosquitto/issues/35
[#274]: https://github.com/eclipse-mosquitto/mosquitto/issues/274
[#448]: https://github.com/eclipse-mosquitto/mosquitto/issues/448
[#478]: https://github.com/eclipse-mosquitto/mosquitto/issues/478
[#522]: https://github.com/eclipse-mosquitto/mosquitto/issues/522
[#737]: https://github.com/eclipse-mosquitto/mosquitto/issues/737
[#1367]: https://github.com/eclipse-mosquitto/mosquitto/issues/1367
[#1369]: https://github.com/eclipse-mosquitto/mosquitto/issues/1369
[#1374]: https://github.com/eclipse-mosquitto/mosquitto/issues/1374
[#1390]: https://github.com/eclipse-mosquitto/mosquitto/issues/1390
[#1391]: https://github.com/eclipse-mosquitto/mosquitto/issues/1391
[#1401]: https://github.com/eclipse-mosquitto/mosquitto/issues/1401
[#1402]: https://github.com/eclipse-mosquitto/mosquitto/issues/1402
