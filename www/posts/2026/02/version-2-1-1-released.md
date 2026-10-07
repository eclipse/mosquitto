<!--
.. title: Version 2.1.1 released.
.. slug: version-2-1-1-released
.. date: 2026-02-04 22:30:00 UTC
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.1.1 of Mosquitto has been released. This is a bugfix release.

# Broker

- Fix PUID/PGID checking for docker
- Add `MOSQUITTO_UNSAFE_ALLOW_SYMLINKS` environment variable to allow the
  restrictions on reading files through symlinks to be lifted in safe
  environments like kubernetes. Closes [#3461].
- Fix inconsistent disconnect log message format, and add address:port.
- Fix `plugin`/`global_plugin` option not allowing space characters.
- Fix $SYS load values not being published initially. Closes [#3459].
- Fix `max_connections not being honoured on libwebsockets listeners. This does
  not affect the built-in websockets support. Closes [#3455].
- Don't enforce receive-maximum, just log a warning. This allows badly
  behaving clients to be fixed. Closes [#3471].

# Plugins
- Fix incorrect linking of libmosquitto_common.so for the acl and password
  file plugins. Closes [#3460].

# Build
- Fix building with WITH_TLS=no

[#3455]: https://github.com/eclipse-mosquitto/mosquitto/issues/3455
[#3459]: https://github.com/eclipse-mosquitto/mosquitto/issues/3459
[#3460]: https://github.com/eclipse-mosquitto/mosquitto/issues/3460
[#3461]: https://github.com/eclipse-mosquitto/mosquitto/issues/3461
[#3471]: https://github.com/eclipse-mosquitto/mosquitto/issues/3471
