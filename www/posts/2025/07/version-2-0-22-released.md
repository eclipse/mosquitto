<!--
.. title: Version 2.0.22 released.
.. slug: version-2-0-22-released
.. date: 2025-07-11 21:40:38 UTC
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.0.22 of Mosquitto has been released. This is a bugfix release.

# Broker

- Windows: Fix broker crash on startup if using `log_dest stdout`
- Bridge: Fix `idle_timeout` never occurring for lazy bridges.
- Fix case where `max_queued_messages = 0` was not treated as unlimited.
  Closes [#3244].
- Fix `--version` exit code and output. Closes [#3267].
- Fix crash on receiving a $CONTROL message over a bridge, if
  `per_listener_settings` is set true and the bridge is carrying out topic
  remapping. Closes [#3261].
- Fix incorrect reference clock being selected on startup on Linux.
  Closes [#3238].
- Fix reporting of client disconnections being incorrectly attributed to "out
  of memory". Closes [#3253].
- Fix compilation when using `WITH_OLD_KEEPALIVE`. Closes [#3250].
- Add Windows linker file for the broker to the installer. Closes [#3269].
- Fix Websockets PING not being sent on Windows. Closes [#3272].
- Fix problems with secure websockets. Closes [#1211].
- Fix crash on exit when using `WITH_EPOLL=no`. Closes [#3302].
- Fix clients being incorrectly expired when they have keepalive ==
  `max_keepalive`. Closes [#3226], [#3286].

# Dynamic security plugin
- Fix mismatch memory free when saving config which caused memory tracking to
  be incorrect.

# Client library
- Fix C++ symbols being removed when compiled with link time optimisation.
  Closes [#3259].
- TLS error handling was incorrectly setting a protocol error for non-TLS
  errors.  This would cause the `mosquitto_loop_start()` thread to exit if no
  broker was available on the first connection attempt. This has been fixed.
  Closes [#3258].
- Fix linker errors on some architectures using cmake. Closes [#3167].


Tests:
- Fix 08-ssl-connect-cert-auth-expired and 08-ssl-connect-cert-auth-revoked
  tests when running on a single CPU system. Closes [#3230].

[#1211]: https://github.com/eclipse-mosquitto/mosquitto/issues/1211
[#3167]: https://github.com/eclipse-mosquitto/mosquitto/issues/3167
[#3226]: https://github.com/eclipse-mosquitto/mosquitto/issues/3226
[#3230]: https://github.com/eclipse-mosquitto/mosquitto/issues/3230
[#3238]: https://github.com/eclipse-mosquitto/mosquitto/issues/3238
[#3244]: https://github.com/eclipse-mosquitto/mosquitto/issues/3244
[#3250]: https://github.com/eclipse-mosquitto/mosquitto/issues/3250
[#3253]: https://github.com/eclipse-mosquitto/mosquitto/issues/3253
[#3258]: https://github.com/eclipse-mosquitto/mosquitto/issues/3258
[#3259]: https://github.com/eclipse-mosquitto/mosquitto/issues/3259
[#3261]: https://github.com/eclipse-mosquitto/mosquitto/issues/3261
[#3267]: https://github.com/eclipse-mosquitto/mosquitto/issues/3267
[#3269]: https://github.com/eclipse-mosquitto/mosquitto/issues/3269
[#3272]: https://github.com/eclipse-mosquitto/mosquitto/issues/3272
[#3286]: https://github.com/eclipse-mosquitto/mosquitto/issues/3286
[#3302]: https://github.com/eclipse-mosquitto/mosquitto/issues/3302
