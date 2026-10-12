<!--
.. title: Version 2.0.21 released.
.. slug: version-2-0-21-released
.. date: 2025-03-06 14:53:38 UTC
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.0.21 of Mosquitto has been released. This is a security and bugfix release.

Security:
- Fix leak on malicious SUBSCRIBE by authenticated client.
  Closes [eclipse #248].
- Further fix for CVE-2023-28366.

# Broker
- Fix clients sending a RESERVED packet not being quickly disconnected.
  Closes [#2325].
- Fix `bind_interface` producing an error when used with an interface that has
  an IPv6 link-local address and no other IPv6 addresses. Closes [#2696].
- Fix mismatched wrapped/unwrapped memory alloc/free in properties. Closes [#3192].
- Fix `allow_anonymous false` not being applied in local only mode. Closes [#3198].
- Add `retain_expiry_interval` option to fix expired retained message not
  being removed from memory if they are not subscribed to. Closes [#3221].
- Produce an error if invalid combinations of cafile/capath/certfile/keyfile
  are used. Closes [#1836]. Closes [#3130].
- Backport keepalive checking from develop to fix problems in current
  implementation. Closes [#3138].

# Client library
- Fix potential deadlock in mosquitto_sub if `-W` is used. Closes [#3175].

# Apps
- mosquitto_ctrl dynsec now also allows `-i` to specify a clientid as well as
  `-c`. This matches the documentation which states `-i`. Closes [#3219].
Client library:
- Fix threads linking on Windows for static libmosquitto library
  Closes [#3143]

# Build
- Fix Windows builds not having websockets enabled.
- Add tzdata to docker images

# Tests
- Fix 08-ssl-connect-cert-auth-expired and 08-ssl-connect-cert-auth-revoked
  tests when under load. Closes [#3208].

[#eclipse 248]: https://gitlab.eclipse.org/security/vulnerability-reports/-/issues/248
[#1836]: https://github.com/eclipse-mosquitto/mosquitto/issues/1836
[#2325]: https://github.com/eclipse-mosquitto/mosquitto/issues/2325
[#2696]: https://github.com/eclipse-mosquitto/mosquitto/issues/2696
[#3130]: https://github.com/eclipse-mosquitto/mosquitto/issues/3130
[#3138]: https://github.com/eclipse-mosquitto/mosquitto/issues/3138
[#3143]: https://github.com/eclipse-mosquitto/mosquitto/issues/3143
[#3175]: https://github.com/eclipse-mosquitto/mosquitto/issues/3175
[#3192]: https://github.com/eclipse-mosquitto/mosquitto/issues/3192
[#3198]: https://github.com/eclipse-mosquitto/mosquitto/issues/3198
[#3208]: https://github.com/eclipse-mosquitto/mosquitto/issues/3208
[#3219]: https://github.com/eclipse-mosquitto/mosquitto/issues/3219
[#3221]: https://github.com/eclipse-mosquitto/mosquitto/issues/3221
