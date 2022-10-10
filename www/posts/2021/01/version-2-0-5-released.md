<!--
.. title: Version 2.0.5 released.
.. slug: version-2-0-5-released
.. date: 2021-01-11 10:29:16 UTC+00:00
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.0.5 of Mosquitto has been released. This is a bugfix release.

# Broker
- Fix `auth_method` not being provided to the extended auth plugin event.
  Closes [#1975].
- Fix large packets not being completely published to slow clients.
  Closes [#1977].
- Fix bridge connection not relinquishing POLLOUT after messages are sent.
  Closes [#1979].
- Fix apparmor incorrectly denying access to
  /var/lib/mosquitto/mosquitto.db.new. Closes [#1978].
- Fix potential intermittent initial bridge connections when using poll().
- Fix `bind_interface` option. Closes [#1999].
- Fix invalid behaviour in dynsec plugin if a group or client is deleted
  before a role that was attached to the group or client is deleted.
  Closes [#1998].
- Improve logging in dynsec addGroupRole command. Closes [#2005].
- Improve logging in dynsec addGroupClient command. Closes [#2008].

# Client library
- Improve documentation around the `_v5()` and non-v5 functions, e.g.
  `mosquitto_publish()` and `mosquitto_publish_v5().

# Build
- `install` Makefile target should depend on `all`, not `mosquitto`, to ensure
  that man pages are always built. Closes [#1989].
- Fixes for lots of minor build warnings highlighted by Visual Studio.

# Apps
- Disallow control characters in mosquitto_passwd usernames.
- Fix incorrect description in mosquitto_ctrl man page. Closes [#1995].
- Fix `mosquitto_ctrl dynsec getGroup` not showing roles. Closes [#1997].


[#1975]: https://github.com/eclipse/mosquitto/issues/1975
[#1977]: https://github.com/eclipse/mosquitto/issues/1977
[#1978]: https://github.com/eclipse/mosquitto/issues/1978
[#1979]: https://github.com/eclipse/mosquitto/issues/1979
[#1989]: https://github.com/eclipse/mosquitto/issues/1989
[#1995]: https://github.com/eclipse/mosquitto/issues/1995
[#1997]: https://github.com/eclipse/mosquitto/issues/1997
[#1998]: https://github.com/eclipse/mosquitto/issues/1998
[#1999]: https://github.com/eclipse/mosquitto/issues/1999
[#2005]: https://github.com/eclipse/mosquitto/issues/2005
[#2008]: https://github.com/eclipse/mosquitto/issues/2008
