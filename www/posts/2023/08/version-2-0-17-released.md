<!--
.. title: Version 2.0.17 released.
.. slug: version-2-0-17-released
.. date: 2023-08-16 12:57:38 UTC+1
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.0.17 of Mosquitto has been released. This is a bugfix release.

Broker:
- Fix `max_queued_messages 0` stopping clients from receiving messages.
  Closes [#2879].
- Fix `max_inflight_messages` not being set correctly. Closes [#2876].

Apps:
- Fix `mosquitto_passwd -U` backup file creation. Closes [#2873].

[#2873]: https://github.com/eclipse-mosquitto/mosquitto/issues/2873
[#2876]: https://github.com/eclipse-mosquitto/mosquitto/issues/2876
[#2879]: https://github.com/eclipse-mosquitto/mosquitto/issues/2879
