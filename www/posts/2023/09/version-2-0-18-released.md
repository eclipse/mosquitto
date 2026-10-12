<!--
.. title: Version 2.0.18 released.
.. slug: version-2-0-18-released
.. date: 2023-09-18 22:18:38 UTC+1
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.0.18 of Mosquitto has been released. This is a bugfix release.

Broker:
- Fix crash on subscribe under certain unlikely conditions. Closes [#2885].
  Closes [#2881].

Clients:
- Fix mosquitto_rr not honouring `-R`. Closes [#2893].

[#2881]: https://github.com/eclipse-mosquitto/mosquitto/issues/2881
[#2885]: https://github.com/eclipse-mosquitto/mosquitto/issues/2885
[#2893]: https://github.com/eclipse-mosquitto/mosquitto/issues/2893
