<!--
.. title: Version 2.0.4 released.
.. slug: version-2-0-4-released
.. date: 2020-12-17 14:22:16 UTC+00:00
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.0.4 of Mosquitto has been released. This is a bugfix release.

# Broker
- Fix $SYS/broker/publish/messages/+ counters not being updated for QoS 1, 2
  messages. Closes [#1968].
- `mosquitto_connect_bind_async()` and `mosquitto_connect_bind_v5()` should not
  reset the bind address option if called with `bind_address == NULL`.
- Fix dynamic security configuration possibly not being reloaded on Windows
  only. Closes [#1962].
- Add more log messages for dynsec load/save error conditions.
- Fix websockets connections blocking non-websockets connections on Windows.
  Closes [#1934].

# Build
- Fix man pages not being built when using CMake. Closes [#1969].

[#1934]: https://github.com/eclipse/mosquitto/issues/1934
[#1962]: https://github.com/eclipse/mosquitto/issues/1962
[#1968]: https://github.com/eclipse/mosquitto/issues/1968
[#1969]: https://github.com/eclipse/mosquitto/issues/1969
