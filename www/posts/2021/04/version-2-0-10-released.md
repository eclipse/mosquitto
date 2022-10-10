<!--
.. title: Version 2.0.10 released.
.. slug: version-2-0-10-released
.. date: 2021-04-03 11:54:38 UTC+1
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Versions 2.0.10 of Mosquitto has been released. This is a security and bugfix
release.

# Security
- [CVE-2021-23980]: If an authenticated client connected with MQTT v5 sent a
  malformed CONNACK message to the broker a NULL pointer dereference occurred,
  most likely resulting in a segfault. This will be updated with the CVE
  number when it is assigned.
  Affects versions 2.0.0 to 2.0.9 inclusive.

# Broker
- Don't overwrite new receive-maximum if a v5 client connects and takes over
  an old session. Closes [#2134].
- Fix CVE-xxxx-xxxx. Closes [#2163].

# Clients
- Set `receive-maximum` to not exceed the `-C` message count in mosquitto_sub
  and mosquitto_rr, to avoid potentially lost messages. Closes [#2134].
- Fix TLS-PSK mode not working with port 8883. Closes [#2152].

# Client library
- Fix possible socket leak. This would occur if a client was using
  `mosquitto_loop_start()`, then if the connection failed due to the remote
  server being inaccessible they called `mosquitto_loop_stop(, true)` and
  recreated the mosquitto object.

# Build
- A variety of minor build related fixes, like functions not having previous
  declarations.
- Fix CMake cross compile builds not finding opensslconf.h. Closes [#2160].
- Fix build on Solaris non-sparc. Closes [#2136].

[CVE-2021-23980]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28166
[#2134]: https://github.com/eclipse/mosquitto/issues/2134
[#2136]: https://github.com/eclipse/mosquitto/issues/2136
[#2152]: https://github.com/eclipse/mosquitto/issues/2152
[#2160]: https://github.com/eclipse/mosquitto/issues/2160
[#2163]: https://github.com/eclipse/mosquitto/issues/2163
