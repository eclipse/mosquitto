<!--
.. title: Version 1.5.1 released
.. slug: version-151-released
.. date: 2018-08-16 17:01:08 UTC+01:00
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

This is a bugfix release.

# Packaging changes

* The snap package now has support for websockets included.
* The Windows packages have changed.
    - Support for Windows XP was dropped in Mosquitto 1.5, so the need for the
	  Cygwin build has gone, and this has been dropped.
    - There are now 64-bit and 32-bit native packages.
    - Websockets support is included.
    - Threading support is not included in libmosquitto to simplify installation,
	  alternative solutions are being looked into for the future.
    - The only external dependency is now OpenSSL.

# Version 1.5.1 changes

## Broker
- Fix plugin cleanup function not being called on exit of the broker. Closes
  [#900].
- Print more OpenSSL errors when loading certificates/keys fail.
- Use `AF_UNSPEC` etc. instead of `PF_UNSPEC` to comply with POSIX. Closes
  [#863].
- Remove use of `AI_ADDRCONFIG`, which means the broker can be used on systems
  where only the loopback interface is defined. Closes [#869], Closes [#901].
- Fix IPv6 addresses not being able to be used as bridge addresses.
  Closes [#886].
- All clients now time out if they exceed their keepalive\*1.5, rather than
  just reach it. This was inconsistent in two places.
- Fix segfault on startup if bridge CA certificates could not be read.
  Closes [#851].
- Fix problem opening listeners on Pi caused by unsigned char being default.
  Found via [#849].
- ACL patterns that do not contain either `%c` or `%u` now produce a warning in
  the log. Closes [#209].
- Fix bridge publishing failing when `per_listener_settings` was true. Closes
  [#860].
- Fix `use_identity_as_username true` not working. Closes [#833].
- Fix UNSUBACK messages not being logged. Closes [#903].
- Fix possible endian issue when reading the `memory_limit` option.
- Fix building for libwebsockets < 1.6.
- Fix accessor functions for username and client id when used in plugin auth
  check.

## Library
- Fix some places where return codes were incorrect, including to the
  `on_disconnect()` callback. This has resulted in two new error codes,
  `MOSQ_ERR_KEEPALIVE` and `MOSQ_ERR_LOOKUP`.
- Fix connection problems when `mosquitto_loop_start()` was called before
  `mosquitto_connect_async()`. Closes [#848].

## Clients
- When compiled using `WITH_TLS=no`, the default port was incorrectly being set
  to -1. This has been fixed.
- Fix compiling on Mac OS X <10.12. Closes `#813` and `#240`.

## Build
- Fixes for building on NetBSD. Closes `#258`.
- Fixes for building on FreeBSD.
- Add support for compiling with static libwebsockets library.


[#209]: https://github.com/eclipse/mosquitto/issues/209
[#240]: https://github.com/eclipse/mosquitto/issues/240
[#258]: https://github.com/eclipse/mosquitto/issues/258
[#813]: https://github.com/eclipse/mosquitto/issues/813
[#833]: https://github.com/eclipse/mosquitto/issues/833
[#848]: https://github.com/eclipse/mosquitto/issues/848
[#849]: https://github.com/eclipse/mosquitto/issues/849
[#851]: https://github.com/eclipse/mosquitto/issues/851
[#860]: https://github.com/eclipse/mosquitto/issues/860
[#863]: https://github.com/eclipse/mosquitto/issues/863
[#869]: https://github.com/eclipse/mosquitto/issues/869
[#886]: https://github.com/eclipse/mosquitto/issues/886
[#900]: https://github.com/eclipse/mosquitto/issues/900
[#901]: https://github.com/eclipse/mosquitto/issues/901
[#903]: https://github.com/eclipse/mosquitto/issues/903
