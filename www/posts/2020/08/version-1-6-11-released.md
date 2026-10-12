<!--
.. title: Version 1.6.11 released.
.. slug: version-1-6-11-released
.. date: 2020-08-11 12:09:13 UTC+00:00
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Mosquitto 1.6.11 has been released, this is a bugfix release.

# Security
- On Windows the Mosquitto service was being installed without appropriate
  path quoting, this has been fixed. Closes [#565671].

# Broker
- Fix usage message only mentioning v3.1.1. Closes [#1713].
- Fix broker refusing to start if only websockets listeners were defined.
  Closes [#1740].
- Change systemd unit files to create /var/log/mosquitto before starting.
  Closes [#821].
- Don't quit with an error if opening the log file isn't possible.
  Closes [#821].
- Fix bridge topic remapping when using "" as the topic. Closes [#1749].
- Fix messages being queued for disconnected bridges when clean start was
  set to true. Closes [#1729].
- Fix `autosave_interval` not being triggered by messages being delivered.
  Closes [#1726].
- Fix websockets clients sometimes not being disconnected promptly.
  Closes [#1718].
- Fix "slow" file based logging by switching to line based buffering.
  Closes [#1689]. Closes [#1741].
- Log protocol error message where appropriate from a bad UNSUBSCRIBE, rather
  than the generic "socket error".
- Don't try to start DLT logging if DLT unavailable, to avoid a long delay
  when shutting down the broker. Closes [#1735].
- Fix potential memory leaks. Closes [#1773]. Closes [#1774].
- Fix clients not receiving messages after a previous client with the same
  client ID and positive will delay interval quit. Closes [#1752].
- Fix overly broad `HAVE_PTHREAD_CANCEL` compile guard. Closes [#1547].

# Client library
- Improved documentation around connect callback return codes. Close [#1730].
- Fix `mosquitto_publish*()` no longer returning `MOSQ_ERR_NO_CONN` when not
  connected. Closes [#1725].
- `mosquitto_loop_start()` now sets a thread name on Linux, FreeBSD, NetBSD,
  and OpenBSD. Closes [#1777].
- Fix `mosquitto_loop_stop()` not stopping on Windows. Closes [#1748]. Closes [#117].


[#117]: https://github.com/eclipse-mosquitto/mosquitto/issues/117
[#821]: https://github.com/eclipse-mosquitto/mosquitto/issues/821
[#1547]: https://github.com/eclipse-mosquitto/mosquitto/issues/1547
[#1689]: https://github.com/eclipse-mosquitto/mosquitto/issues/1689
[#1713]: https://github.com/eclipse-mosquitto/mosquitto/issues/1713
[#1718]: https://github.com/eclipse-mosquitto/mosquitto/issues/1718
[#1725]: https://github.com/eclipse-mosquitto/mosquitto/issues/1725
[#1726]: https://github.com/eclipse-mosquitto/mosquitto/issues/1726
[#1729]: https://github.com/eclipse-mosquitto/mosquitto/issues/1729
[#1730]: https://github.com/eclipse-mosquitto/mosquitto/issues/1730
[#1735]: https://github.com/eclipse-mosquitto/mosquitto/issues/1735
[#1740]: https://github.com/eclipse-mosquitto/mosquitto/issues/1740
[#1741]: https://github.com/eclipse-mosquitto/mosquitto/issues/1741
[#1748]: https://github.com/eclipse-mosquitto/mosquitto/issues/1748
[#1749]: https://github.com/eclipse-mosquitto/mosquitto/issues/1749
[#1752]: https://github.com/eclipse-mosquitto/mosquitto/issues/1752
[#1773]: https://github.com/eclipse-mosquitto/mosquitto/issues/1773
[#1774]: https://github.com/eclipse-mosquitto/mosquitto/issues/1774
[#1777]: https://github.com/eclipse-mosquitto/mosquitto/issues/1777
[#565671]: https://bugs.eclipse.org/bugs/show_bug.cgi?id=565671
