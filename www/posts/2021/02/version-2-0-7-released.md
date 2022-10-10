<!--
.. title: Version 2.0.7 released.
.. slug: version-2-0-7-released
.. date: 2021-02-04 10:02:38 UTC
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.0.7 and 1.6.13 of Mosquitto have been released. These are bugfix releases.

# 2.0.7

## Broker
- Fix exporting of executable symbols on BSD when building via makefile.
- Fix some minor memory leaks on exit only.
- Fix possible memory leak on connect. Closes [#2057].
- Fix openssl engine not being able to load private key. Closes [#2066].

## Clients
- Fix config files truncating options after the first space. Closes [#2059].

## Build
- Fix man page building to not absolutely require xsltproc when using CMake.
  This now handles the case where we are building from the released tar, or
  building from git if xsltproc is available, or building from git if xsltproc
  is not available.


# 1.6.13

## Broker:
- Fix crash on Windows if loading a plugin fails. Closes [#1866].
- Fix DH group not being set for TLS connections, which meant ciphers using
  DHE couldn't be used. Closes [#1925]. Closes [#1476].
- Fix local bridges being disconnected on SIGHUP. Closes [#1942].
- Fix $SYS/broker/publish/messages/+ counters not being updated for QoS 1, 2
  messages. Closes [#1968].
- Fix listener not being reassociated with client when reloading a persistence
  file and `per_listener_settings true` is set and the client did not set a
  username. Closes [#1891].
- Fix file logging on Windows. Closes [#1880].
- Fix bridge sock not being removed from sock hash on error. Closes [#1897].

## Client library:
- Fix build on Mac Big Sur. Closes [#1905].
- Fix DH group not being set for TLS connections, which meant ciphers using
  DHE couldn't be used. Closes [#1925]. Closes [#1476].

## Clients:
- mosquitto_sub will now quit with an error if the %U option is used on
  Windows, rather than just quitting. Closes [#1908].
- Fix config files truncating options after the first space. Closes [#2059].

## Apps:
- Perform stricter parsing of input username in mosquitto_passwd. Closes
  [#570126] (Eclipse bugzilla).

## Build:
- Enable epoll support in CMake builds.

[#1476]: https://github.com/eclipse/mosquitto/issues/1476
[#1866]: https://github.com/eclipse/mosquitto/issues/1866
[#1880]: https://github.com/eclipse/mosquitto/issues/1880
[#1891]: https://github.com/eclipse/mosquitto/issues/1891
[#1897]: https://github.com/eclipse/mosquitto/issues/1897
[#1905]: https://github.com/eclipse/mosquitto/issues/1905
[#1908]: https://github.com/eclipse/mosquitto/issues/1908
[#1925]: https://github.com/eclipse/mosquitto/issues/1925
[#1942]: https://github.com/eclipse/mosquitto/issues/1942
[#1968]: https://github.com/eclipse/mosquitto/issues/1968
[#2057]: https://github.com/eclipse/mosquitto/issues/2057
[#2059]: https://github.com/eclipse/mosquitto/issues/2059
[#2066]: https://github.com/eclipse/mosquitto/issues/2066
[#570126]: https://bugs.eclipse.org/bugs/show_bug.cgi?id=570126
