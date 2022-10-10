<!--
.. title: Version 1.5.2 released
.. slug: version-152-released
.. date: 2018-09-19 18:18:36 UTC+01:00
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

This is a bugfix release.

# Version 1.5.2 changes

## Broker
- Fix build when using `WITH_ADNS=yes`.
- Fix incorrect call to setsockopt() for `TCP_NODELAY`. Closes [#941].
- Fix excessive CPU usage when the number of sockets exceeds the system limit.
  Closes [#948].
- Fix for bridge connections when using `WITH_ADNS=yes`.
- Fix `round_robin false` behaviour. Closes [#481].
- Fix segfault on HUP when bridges and security options are configured.
  Closes [#965].

## Library
- Fix situation where username and password is used with SOCKS5 proxy. Closes
  [#927].
- Fix SOCKS5 behaviour when passing IP addresses. Closes [#927].

## Build
- Make it easier to build without bundled uthash.h using `WITH_BUNDLED_DEPS=no`.
- Fix build with OPENSSL_NO_ENGINE. Closes [#932].

[#481]: https://github.com/eclipse/mosquitto/issues/481
[#927]: https://github.com/eclipse/mosquitto/issues/927
[#932]: https://github.com/eclipse/mosquitto/issues/932
[#941]: https://github.com/eclipse/mosquitto/issues/941
[#948]: https://github.com/eclipse/mosquitto/issues/948
[#965]: https://github.com/eclipse/mosquitto/issues/965
