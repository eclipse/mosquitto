<!--
.. title: Version 2.1.2 released.
.. slug: version-2-1-2-released
.. date: 2026-02-09 09:30:00 UTC
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.1.2 of Mosquitto has been released. This is a bugfix release.

# Broker:
- Forbid running with `persistence true` and with a persistence plugin at the
  same time. Closes [#3480].

# Build:
- Build fixes for OpenBSD. Closes [#3474].
- Add missing libedit to docker builds. Closes [#3476].
- Fix static/shared linking of libwebsockets under cmake.

[#3474]: https://github.com/eclipse-mosquitto/mosquitto/issues/3474
[#3476]: https://github.com/eclipse-mosquitto/mosquitto/issues/3476
[#3480]: https://github.com/eclipse-mosquitto/mosquitto/issues/3480
