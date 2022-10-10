<!--
.. title: Version 2.0.15 released.
.. slug: version-2-0-15-released
.. date: 2022-08-16 12:57:38 UTC+1
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Versions 2.0.15 of Mosquitto has been released. This is a security
and bugfix release.

# Security
- Deleting the group configured as the anonymous group in the Dynamic Security
  plugin, would leave a dangling pointer that could lead to a single crash.
  This is considered a minor issue - only administrative users should have
  access to dynsec, the impact on availability is one-off, and there is no
  associated loss of data. It is now forbidden to delete the group configured
  as the anonymous group.

# Broker
- Fix memory leak when a plugin modifies the topic of a message in
  `MOSQ_EVT_MESSAGE`.
- Fix bridge `restart_timeout` not being honoured.
- Fix potential memory leaks if a plugin modifies the message in the
  `MOSQ_EVT_MESSAGE` event.
- Fix unused flags in CONNECT command being forced to be 0, which is not
  required for MQTT v3.1. Closes [#2522].
- Improve documentation of `persistent_client_expiration` option.
  Closes [#2404].
- Add clients to session expiry check list when restarting and reloading from
  persistence. Closes [#2546].
- Fix bridges not sending failure notification messages to the local broker if
  the remote bridge connection fails. Closes [#2467]. Closes [#1488].
- Fix some PUBLISH messages not being counted in $SYS stats. Closes [#2448].
- Fix incorrect return code being sent in DISCONNECT when a client session is
  taken over. Closes [#2607].
- Fix confusing "out of memory" error when a client is kicked in the dynamic
  security plugin. Closes [#2525].
- Fix confusing error message when dynamic security config file was a
  directory. Closes [#2520].
- Fix bridge queued messages not being persisted when local_cleansession is
  set to false and cleansession is set to true. Closes [#2604].
- Dynamic security: Fix modifyClient and modifyGroup commands to not modify
  the client/group if a new group/client being added is not valid.
  Closes [#2598].
- Dynamic security: Fix the plugin being able to be loaded twice. Currently
  only a single plugin can interact with a unique $CONTROL topic. Using
  multiple instances of the plugin would produce duplicate entries in the
  config file. Closes [#2601]. Closes [#2470].
- Fix case where expired messages were causing queued messages not to be
  delivered. Closes [#2609].
- Fix websockets not passing on the X-Forwarded-For header.

# Client library
- Fix threads library detection on Windows under cmake. Bumps the minimum
  cmake version to 3.1, which is still ancient.
- Fix use of `MOSQ_OPT_TLS_ENGINE` being unable to be used due to the openssl
  ctx not being initialised until starting to connect. Closes [#2537].
- Fix incorrect use of SSL_connect. Closes [#2594].
- Don't set SIGPIPE to ignore, use MSG_NOSIGNAL instead. Closes [#2564].
- Add documentation of struct mosquitto_message to header. Closes [#2561].
- Fix documentation omission around mosquitto_reinitialise. Closes [#2489].
- Fix use of MOSQ_OPT_SSL_CTX when used in conjunction with
  MOSQ_OPT_SSL_CTX_DEFAULTS. Closes [#2463].
- Fix failure to close thread in some situations. Closes [#2545].

# Clients
- Fix mosquitto_pub incorrectly reusing topic aliases when reconnecting.
  Closes [#2494].

# Apps
- Fix `-o` not working in `mosquitto_ctrl`, and typo in related documentation.
  Closes [#2471].


[#1488]: https://github.com/eclipse/mosquitto/issues/1488
[#2404]: https://github.com/eclipse/mosquitto/issues/2404
[#2448]: https://github.com/eclipse/mosquitto/issues/2448
[#2463]: https://github.com/eclipse/mosquitto/issues/2463
[#2467]: https://github.com/eclipse/mosquitto/issues/2467
[#2470]: https://github.com/eclipse/mosquitto/issues/2470
[#2471]: https://github.com/eclipse/mosquitto/issues/2471
[#2489]: https://github.com/eclipse/mosquitto/issues/2489
[#2494]: https://github.com/eclipse/mosquitto/issues/2494
[#2520]: https://github.com/eclipse/mosquitto/issues/2520
[#2522]: https://github.com/eclipse/mosquitto/issues/2522
[#2525]: https://github.com/eclipse/mosquitto/issues/2525
[#2537]: https://github.com/eclipse/mosquitto/issues/2537
[#2545]: https://github.com/eclipse/mosquitto/issues/2545
[#2546]: https://github.com/eclipse/mosquitto/issues/2546
[#2561]: https://github.com/eclipse/mosquitto/issues/2561
[#2564]: https://github.com/eclipse/mosquitto/issues/2564
[#2594]: https://github.com/eclipse/mosquitto/issues/2594
[#2598]: https://github.com/eclipse/mosquitto/issues/2598
[#2601]: https://github.com/eclipse/mosquitto/issues/2601
[#2604]: https://github.com/eclipse/mosquitto/issues/2604
[#2607]: https://github.com/eclipse/mosquitto/issues/2607
[#2609]: https://github.com/eclipse/mosquitto/issues/2609
