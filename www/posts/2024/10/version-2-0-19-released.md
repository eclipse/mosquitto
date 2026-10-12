<!--
.. title: Version 2.0.19 released.
.. slug: version-2-0-19-released
.. date: 2024-10-02 10:46:38 UTC+1
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.0.19 of Mosquitto has been released. This is a security and bugfix release.

# Security
- Fix mismatched subscribe/unsubscribe with normal/shared topics.
- Fix crash on bridge using remapped topic being sent a crafted packet.
- Don't allow SUBACK with missing reason codes in client library.

# Broker
- Fix assert failure when loading a persistence file that contains
  subscriptions with no client id.
- Fix local bridges being incorrectly expired when `persistent_client_expiration`
  is in use.
- Fix use of CLOCK_BOOTTIME for getting time. Closes [#3089].
- Fix mismatched subscribe/unsubscribe with normal/shared topics.
- Fix crash on bridge using remapped topic being sent a crafted packet.

# Client library
- Fix some error codes being converted to string as "unknown". Closes [#2579].
- Clear SSL error state to avoid spurious error reporting. Closes [#3054].
- Fix "payload format invalid" not being allowed as a PUBREC reason code.
- Don't allow SUBACK with missing reason codes.

# Build
- Thread support is re-enabled on Windows.

[#2579]: https://github.com/eclipse-mosquitto/mosquitto/issues/2579
[#3054]: https://github.com/eclipse-mosquitto/mosquitto/issues/3054
[#3089]: https://github.com/eclipse-mosquitto/mosquitto/issues/3089
