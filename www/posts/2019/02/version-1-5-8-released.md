<!--
.. title: Version 1.5.8 released
.. slug: version-1-5-8-released
.. date: 2019-02-28 17:01:00 UTC
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

This is a bugfix release.

## Broker
- Fix clients being disconnected when ACLs are in use. This only affects the
  case where a client connects using a username, and the anonymous ACL list is
  defined but specific user ACLs are not defined. Closes [#1162].
- Make error messages for missing config file clearer.
- Fix some Coverity Scan reported errors that could occur when the broker was
  already failing to start.
- Fix broken `mosquitto_passwd` on FreeBSD. Closes [#1032].
- Fix delayed bridge local subscriptions causing missing messages.
  Closes [#1174].

## Library
- Use higher resolution timer for random initialisation of client id
  generation. Closes [#1177].
- Fix some Coverity Scan reported errors that could occur when the library was
  already quitting.

[#1032]: https://github.com/eclipse-mosquitto/mosquitto/issues/1032
[#1162]: https://github.com/eclipse-mosquitto/mosquitto/issues/1162
[#1174]: https://github.com/eclipse-mosquitto/mosquitto/issues/1174
[#1177]: https://github.com/eclipse-mosquitto/mosquitto/issues/1177
