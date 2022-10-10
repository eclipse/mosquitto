<!--
.. title: Version 1.6.12 released.
.. slug: version-1-6-12-released
.. date: 2020-08-19 14:44:13 UTC+01:00
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Mosquitto 1.6.12 and 1.5.10 have been released.

# Security
- In some circumstances, Mosquitto could leak memory when handling PUBLISH
  messages. This is limited to incoming QoS 2 messages, and is related
  to the combination of the broker having persistence enabled, a clean
  session=false client, which was connected prior to the broker restarting,
  then has reconnected and has now sent messages at a sufficiently high rate
  that the incoming queue at the broker has filled up and hence messages are
  being dropped. This is more likely to have an effect where
  `max_queued_messages` is a small value. This has now been fixed. Closes [#1793].

The following fixes apply to 1.6.12 only.

# Broker
- Build warning fixes when building with `WITH_BRIDGE=no` and `WITH_TLS=no`.

# Clients
- All clients exit with an error exit code on CONNACK failure. Closes [#1778].
- Don't busy loop with `mosquitto_pub -l` on a slow connection.

[#1778]: https://github.com/eclipse/mosquitto/issues/1778
[#1793]: https://github.com/eclipse/mosquitto/issues/1793
