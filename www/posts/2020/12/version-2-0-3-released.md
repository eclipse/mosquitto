<!--
.. title: Version 2.0.3 released.
.. slug: version-2-0-3-released
.. date: 2020-12-17 14:22:16 UTC+00:00
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.0.3 of Mosquitto has been released. This is a bugfix release.

# Security
- Running mosquitto_passwd with the following arguments only
  `mosquitto_passwd -b password_file username password` would cause the
  username to be used as the password.

# Broker
- Fix excessive CPU use on non-Linux systems when the open file limit is set
  high. Closes [#1947].
- Fix LWT not being sent on client takeover when the existing session wasn't
  being continued. Closes [#1946].
- Fix bridges possibly not completing connections when WITH_ADNS is in use.
  Closes [#1960].
- Fix QoS 0 messages not being delivered if max_queued_messages was set to 0.
  Closes [#1956].
- Fix local bridges being disconnected on SIGHUP. Closes [#1942].
- Fix slow initial bridge connections for WITH_ADNS=no.

# Clients
- Fix mosquitto_sub being unable to terminate with Ctrl-C if a successful
  connection is not made. Closes [#1957].

# Apps
- Fix `mosquitto_passwd -b` using username as password (not if `-c` is also
  used). Closes [#1949].

# Build
- Fix `install` target when using WITH_CJSON=no. Closes [#1938].
- Fix `generic` docker build. Closes [#1945].

[#1938]: https://github.com/eclipse/mosquitto/issues/1938
[#1942]: https://github.com/eclipse/mosquitto/issues/1942
[#1945]: https://github.com/eclipse/mosquitto/issues/1945
[#1946]: https://github.com/eclipse/mosquitto/issues/1946
[#1947]: https://github.com/eclipse/mosquitto/issues/1947
[#1949]: https://github.com/eclipse/mosquitto/issues/1949
[#1956]: https://github.com/eclipse/mosquitto/issues/1956
[#1957]: https://github.com/eclipse/mosquitto/issues/1957
[#1960]: https://github.com/eclipse/mosquitto/issues/1960
