<!--
.. title: Version 1.6.10 released.
.. slug: version-1-6-10-released
.. date: 2020-05-25 23:45:13 UTC+00:00
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Mosquitto 1.6.10 has been released, this is a bugfix release.

# Broker
- Report invalid bridge prefix+pattern combinations at config parsing time
  rather than letting the bridge fail later. Issue [#1635].
- Fix `mosquitto_passwd -b` not updating passwords for existing users
  correctly. Creating a new user with `-b` worked without problem.
  Closes [#1664].
- Fix memory leak when connecting clients rejected.
- Don't disconnect clients that are already disconnected. This prevents the
  session expiry being extended on SIGHUP. Closes [#1521].
- Fix support for openssl 3.0.
- Fix check when loading persistence file of a different version than the
  native version. Closes [#1684].
- Fix possible assert crash associated with bridge reconnecting when compiled
  without epoll support. Closes [#1700].

# Client library
- Don't treat an unexpected PUBACK, PUBREL, or PUBCOMP as a fatal error.
  Issue [#1629].
- Fix support for openssl 3.0.
- Fix memory leaks from multiple calls to
  `mosquitto_lib_init()`/`mosquitto_lib_cleanup()`. Closes [#1691].
- Fix documentation on return code of `mosquitto_lib_init()` for Windows.
  Closes [#1690].

# Clients
- Fix mosquitto_sub `%j` or `%J` not working on Windows. Closes [#1674].

# Build
- Various fixes for building with below C99 support. Closes [#1622].
- Fix use of sed on BSD. Closes [#1614].

[#1521]: https://github.com/eclipse/mosquitto/issues/1521
[#1614]: https://github.com/eclipse/mosquitto/issues/1614
[#1622]: https://github.com/eclipse/mosquitto/issues/1622
[#1629]: https://github.com/eclipse/mosquitto/issues/1629
[#1635]: https://github.com/eclipse/mosquitto/issues/1635
[#1664]: https://github.com/eclipse/mosquitto/issues/1664
[#1674]: https://github.com/eclipse/mosquitto/issues/1674
[#1684]: https://github.com/eclipse/mosquitto/issues/1684
[#1690]: https://github.com/eclipse/mosquitto/issues/1690
[#1691]: https://github.com/eclipse/mosquitto/issues/1691
[#1700]: https://github.com/eclipse/mosquitto/issues/1700
