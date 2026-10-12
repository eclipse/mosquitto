<!--
.. title: Version 1.6.1 released
.. slug: version-1-6-1-released
.. date: 2019-04-26 16:37:00 UTC+1
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

This is a minor service release. The fixes are only related to documentation
and the build process, and so is primarily of interest for people building
Mosquitto.

## Broker
- Document `memory_limit` option.

## Clients
- Fix compilation on non glibc systems due to missing sys/time.h header.

## Build:
- Add `make check` target and document testing procedure. Closes [#1230].
- Document bundled dependencies and how to disable. Closes [#1231].
- Split CFLAGS and CPPFLAGS, and LDFLAGS and LDADD/LIBADD.
- test/unit now respects CPPFLAGS and LDFLAGS. Closes [#1232].
- Don't call ldconfig in CMake scripts. Closes [#1048].
- Use `CMAKE_INSTALL_*` variables when installing in CMake. Closes [#1049].

[#1048]: https://github.com/eclipse-mosquitto/mosquitto/issues/1048
[#1049]: https://github.com/eclipse-mosquitto/mosquitto/issues/1049
[#1230]: https://github.com/eclipse-mosquitto/mosquitto/issues/1230
[#1231]: https://github.com/eclipse-mosquitto/mosquitto/issues/1231
[#1232]: https://github.com/eclipse-mosquitto/mosquitto/issues/1232
