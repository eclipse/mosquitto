<!--
.. title: Version 2.0.11 released.
.. slug: version-2-0-11-released
.. date: 2021-06-08 11:54:38 UTC+1
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Versions 2.0.11 and 1.6.15 of Mosquitto has been released. These are a security
and bugfix releases.

# 2.0.11

## Security
- If an authenticated client connected with MQTT v5 sent a crafted CONNECT
  message to the broker a memory leak would occur.
  Affects versions 1.6 to 2.0.10 inclusive.

## Broker
- Fix possible crash having just upgraded from 1.6 if `per_listener_settings
  true` is set, and a SIGHUP is sent to the broker before a client has
  reconnected to the broker. Closes [#2167].
- Fix bridge not reconnectng if the first reconnection attempt fails.
  Closes [#2207].
- Improve QoS 0 outgoing packet queueing.
- Fix non-reachable bridge blocking the broker on Windows. Closes #2172.
- Fix possible corruption of pollfd array on Windows when bridges were
  reconnecting. Closes [#2173].
- Fix QoS 0 messages not being queued when `queue_qos0_messages` was enabled.
  Closes [#2224].

## Clients
- If sending mosquitto_sub output to a pipe, mosquitto_sub will now detect
  that the pipe has closed and disconnect. Closes [#2164].
- Fix `mosquitto_pub -l` quitting if a message publication is attempted when
  the broker is temporarily unavailable. Closes [#2187].

# 1.6.15

## Security
- If an authenticated client connected with MQTT v5 sent a crafted CONNECT
  message to the broker a memory leak would occur.
  Affects versions 1.6 to 2.0.10 inclusive.

[#2164]: https://github.com/eclipse/mosquitto/issues/2164
[#2167]: https://github.com/eclipse/mosquitto/issues/2167
[#2172]: https://github.com/eclipse/mosquitto/issues/2172
[#2173]: https://github.com/eclipse/mosquitto/issues/2173
[#2187]: https://github.com/eclipse/mosquitto/issues/2187
[#2207]: https://github.com/eclipse/mosquitto/issues/2207
[#2224]: https://github.com/eclipse/mosquitto/issues/2224
