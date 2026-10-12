<!--
.. title: Version 1.4.11 released
.. slug: version-1-4-11-released
.. date: 2017-02-21 20:27:39
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

This is a bugfix release.

# Broker

 * Fix crash when "lazy" type bridge attempts to reconnect. Closes [#259].
 * `maximum_connections` now applies to websockets listeners. Closes [#271].
 * Allow bridges to use TLS with IPv6.
 * Don't error on zero length persistence files. Closes [#316].
 * For http only websockets clients, close files served over http in all cases
   when the client disconnects. Closes [#354].
 * Fix error message when websockets `http_dir` directory does not exist.
 * Improve password utility error message. Closes [#379].
 * Bridges can use asynchronous DNS lookups on systems with glibc. This can be
   enabled at compile time using `WITH_ADNS=yes`.

# Clients

 * Use of `--ciphers` no longer requires you to also pass `--tls-version`.
   Closes [#380].

# Client library

 * Clients can now use TLS with IPv6.
 * Fix potential socket leakage when reconnecting. Closes [#304].
 * Fix potential negative timeout being passed to pselect. Closes [#329].

[#259]: https://github.com/eclipse-mosquitto/mosquitto/issues/259
[#271]: https://github.com/eclipse-mosquitto/mosquitto/issues/271
[#304]: https://github.com/eclipse-mosquitto/mosquitto/issues/304
[#316]: https://github.com/eclipse-mosquitto/mosquitto/issues/316
[#329]: https://github.com/eclipse-mosquitto/mosquitto/issues/329
[#354]: https://github.com/eclipse-mosquitto/mosquitto/issues/354
[#379]: https://github.com/eclipse-mosquitto/mosquitto/issues/379
[#380]: https://github.com/eclipse-mosquitto/mosquitto/issues/380
