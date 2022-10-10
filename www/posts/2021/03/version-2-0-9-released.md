<!--
.. title: Version 2.0.9 released.
.. slug: version-2-0-9-released
.. date: 2021-03-11 22:19:38 UTC
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Versions 2.0.9, 1.6.14, and 1.5.11 of Mosquitto have been released. These are
bugfix releases and include a minor security fix.

# 2.0.9

## Security
- If an empty or invalid CA file was provided to the client library for
  verifying the remote broker, then the initial connection would fail but
  subsequent connections would succeed without verifying the remote broker
  certificate. Closes [#2130].
- If an empty or invalid CA file was provided to the broker for verifying the
  remote broker for an outgoing bridge connection then the initial connection
  would fail but subsequent connections would succeed without verifying the
  remote broker certificate. Closes [#2130].

## Broker
- Fix encrypted bridge connections incorrectly connecting when `bridge_cafile`
  is empty or invalid. Closes [#2130].
- Fix `tls_version` behaviour not matching documentation. It was setting the
  exact TLS version to use, not the minimium TLS version to use. Closes [#2110].
- Fix messages to `$` prefixed topics being rejected. Closes [#2111].
- Fix QoS 0 messages not being delivered when max_queued_bytes was configured.
  Closes [#2123].
- Fix bridge increasing backoff calculation.
- Improve handling of invalid combinations of listener address and bind
  interface configurations. Closes [#2081].
- Fix `max_keepalive` option not applying to clients connecting with keepalive
  set to 0. Closes [#2117].

## Client library
- Fix encrypted connections incorrectly connecting when the CA file passed to
  `mosquitto_tls_set()` is empty or invalid. Closes [#2130].
- Fix connections retrying very rapidly in some situations.

## Build
- Fix cmake epoll detection.

# 1.6.14

## Security
- If an empty or invalid CA file was provided to the client library for
  verifying the remote broker, then the initial connection would fail but
  subsequent connections would succeed without verifying the remote broker
  certificate. Closes [#2130].
- If an empty or invalid CA file was provided to the broker for verifying the
  remote broker for an outgoing bridge connection then the initial connection
  would fail but subsequent connections would succeed without verifying the
  remote broker certificate. Closes [#2130].

## Broker
- Fix encrypted bridge connections incorrectly connecting when `bridge_cafile`
  is empty or invalid. Closes [#2130].

## Client library
- Fix encrypted connections incorrectly connecting when the CA file passed to
  `mosquitto_tls_set()` is empty or invalid. Closes [#2130].
- Fix connections retrying very rapidly in some situations.

## Clients
- Fix possible loss of data in `mosquitto_pub -l` when sending multiple long
  lines. Closes [#2078].

# 1.5.11

## Security
- If an empty or invalid CA file was provided to the client library for
  verifying the remote broker, then the initial connection would fail but
  subsequent connections would succeed without verifying the remote broker
  certificate. Closes [#2130].
- If an empty or invalid CA file was provided to the broker for verifying the
  remote broker for an outgoing bridge connection then the initial connection
  would fail but subsequent connections would succeed without verifying the
  remote broker certificate. Closes [#2130].

## Broker
- Fix encrypted bridge connections incorrectly connecting when `bridge_cafile`
  is empty or invalid. Closes [#2130].

## Client library
- Fix encrypted connections incorrectly connecting when the CA file passed to
  `mosquitto_tls_set()` is empty or invalid. Closes [#2130].

[#2040]: https://github.com/eclipse/mosquitto/issues/2040
[#2078]: https://github.com/eclipse/mosquitto/issues/2078
[#2081]: https://github.com/eclipse/mosquitto/issues/2081
[#2110]: https://github.com/eclipse/mosquitto/issues/2110
[#2111]: https://github.com/eclipse/mosquitto/issues/2111
[#2117]: https://github.com/eclipse/mosquitto/issues/2117
[#2123]: https://github.com/eclipse/mosquitto/issues/2123
[#2130]: https://github.com/eclipse/mosquitto/issues/2130
