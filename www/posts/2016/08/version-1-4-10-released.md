<!--
.. title: Version 1.4.10 released
.. slug: version-1-4-10-released
.. date: 2016-08-25 16:04:14
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

This is a bugfix release.

# Broker

 * Fix TLS operation with websockets listeners and libwebsockets 2.x. Closes
   [#186].
 * Don't disconnect client on HUP before reading the pending data. Closes [#7].
 * Fix some $SYS messages being incorrectly persisted. Closes [#191].
 * Support OpenSSL 1.1.0.
 * Call fsync after persisting data to ensure it is correctly written. Closes
   [#189].
 * Fix persistence saving of subscription QoS on big-endian machines.
 * Fix will retained flag handling on Windows. Closes [#222].
 * Broker now displays an error if it is unable to open the log file. Closes
   [#234].

# Client library

 * Support OpenSSL 1.1.0.
 * Fixed the C++ library not allowing SOCKS support to be used. Closes [#198].
 * Fix memory leak when verifying a server certificate with a subjectAltName
   section. Closes [#237].

# Build

 * Don't attempt to install docs when `WITH_DOCS=no`. Closes [#184].

[#7]: https://github.com/eclipse-mosquitto/mosquitto/issues/7
[#184]: https://github.com/eclipse-mosquitto/mosquitto/issues/184
[#186]: https://github.com/eclipse-mosquitto/mosquitto/issues/186
[#189]: https://github.com/eclipse-mosquitto/mosquitto/issues/189
[#191]: https://github.com/eclipse-mosquitto/mosquitto/issues/191
[#198]: https://github.com/eclipse-mosquitto/mosquitto/issues/198
[#222]: https://github.com/eclipse-mosquitto/mosquitto/issues/222
[#234]: https://github.com/eclipse-mosquitto/mosquitto/issues/234
[#237]: https://github.com/eclipse-mosquitto/mosquitto/issues/237
