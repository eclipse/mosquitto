<!--
.. title: Version 2.0.14 released.
.. slug: version-2-0-14-released
.. date: 2021-11-17 00:25:38 UTC
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Versions 2.0.14 of Mosquitto has been released. This is a bugfix release.

# Broker
- Fix bridge not respecting receive-maximum when reconnecting with MQTT v5.

# Client library
- Fix `mosquitto_topic_matches_sub2()` not using the length parameters.
  Closes [#2364].
- Fix incorrect `subscribe_callback` in mosquittopp.h. Closes [#2367].

[#2364]: https://github.com/eclipse/mosquitto/issues/2364
[#2367]: https://github.com/eclipse/mosquitto/issues/2367
