<!--
.. title: Version 2.0.13 released.
.. slug: version-2-0-13-released
.. date: 2021-10-27 16:35:38 UTC+1
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.0.13 of Mosquitto has been released. This is a bugfix release.

# Broker
- Fix `max_keepalive` option not being able to be set to 0.
- Fix LWT messages not being delivered if `per_listener_settings` was set to
  true. Closes [#2314].
- Various fixes around inflight quota management. Closes [#2306].
- Fix problem parsing config files with Windows line endings. Closes [#2297].
- Don't send retained messages when a shared subscription is made.
- Fix log being truncated in Windows.
- Fix client id not showing in log on failed connections, where possible.
- Fix broker sending duplicate CONNACK on failed MQTT v5 reauthentication.
  Closes [#2339].
- Fix mosquitto_plugin.h not including mosquitto_broker.h. Closes [#2350].

# Client library
- Initialise sockpairR/W to invalid in `mosquitto_reinitialise()` to avoid
  closing invalid sockets in `mosquitto_destroy()` on error. Closes [#2326].

# Clients
- Fix date format in mosquitto_sub output. Closes [#2353].

[#2297]: https://github.com/eclipse/mosquitto/issues/2297
[#2306]: https://github.com/eclipse/mosquitto/issues/2306
[#2314]: https://github.com/eclipse/mosquitto/issues/2314
[#2326]: https://github.com/eclipse/mosquitto/issues/2326
[#2339]: https://github.com/eclipse/mosquitto/issues/2339
[#2350]: https://github.com/eclipse/mosquitto/issues/2350
[#2353]: https://github.com/eclipse/mosquitto/issues/2353
