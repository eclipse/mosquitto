<!--
.. title: Version 2.0.2 released.
.. slug: version-2-0-2-released
.. date: 2020-12-10 14:33:16 UTC+00:00
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.0.2 and 2.0.1 of Mosquitto has been released. These are bugfix releases.

Version 2.0.2 fixes a build regression introduced in 2.0.1 when websockets
support was enabled on non-Linux systems.

The 2.0.1 changes are below.

# Broker
- Fix websockets connections on Windows blocking subsequent connections.
  Closes [#1934].
- Fix DH group not being set for TLS connections, which meant ciphers using
  DHE couldn't be used. Closes [#1925]. Closes [#1476].
- Fix websockets listeners not causing the main loop not to wake up.
  Closes [#1936].

# Client library
- Fix DH group not being set for TLS connections, which meant ciphers using
  DHE couldn't be used. Closes [#1925]. Closes [#1476].

# Apps
- Fix `mosquitto_passwd -U`

# Build
- Fix cjson include paths.
- Fix build using WITH_TLS=no when the openssl headers aren't available.
- Distribute cmake/ and snap/ directories in tar.


[#1476]: https://github.com/eclipse/mosquitto/issues/1476
[#1925]: https://github.com/eclipse/mosquitto/issues/1925
[#1934]: https://github.com/eclipse/mosquitto/issues/1934
[#1936]: https://github.com/eclipse/mosquitto/issues/1936
