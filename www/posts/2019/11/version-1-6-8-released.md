<!--
.. title: Version 1.6.8 released.
.. slug: version-1-6-8-released
.. date: 2019-11-28 16:44:19 UTC+00:00
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Mosquitto 1.6.8 has been released, this is a bugfix release.

# Broker
- Various fixes for `allow_zero_length_clientid` config, where this option was
  not being set correctly. Closes [#1429].
- Fix incorrect memory tracking causing problems with `memory_limit` option.
  Closes [#1437].
- Fix subscription topics being limited to 200 characters instead of 200
  hierarchy levels. Closes [#1441].
- Only a single CRL could be loaded at once. This has been fixed.
  Closes [#1442].
- Fix problems with reloading config when `per_listener_settings` was true.
  Closes [#1459].
- Fix retained messages with an expiry interval not being expired after being
  restored from persistence. Closes [#1464].
- Fix messages with an expiry interval being sent without an expiry interval
  property just before they were expired. Closes [#1464].
- Fix TLS Websockets clients not receiving messages after taking over a
  previous connection. Closes [#1489].
- Fix MQTT 3.1.1 clients using clean session false, or MQTT 5.0 clients using
  session-expiry-interval set to infinity never expiring, even when the global
  `persistent_client_expiration` option was set. Closes [#1494].

# Client library
- Fix publish properties not being passed to `on_message_v5()` callback for QoS 2
  messages. Closes [#1432].
- Fix documentation issues in mosquitto.h. Closes [#1478].
- Document `mosquitto_connect_srv()`. Closes [#1499].

# Clients
- Fix duplicate cfg definition in rr_client. Closes [#1453].
- Fix `mosquitto_pub -l` hang when stdin stream ends. Closes [#1448].
- Fix `mosquitto_pub -l` not sending the final line of stdin if it does not
  end with a new line. Closes [#1473].
- Make documentation for `mosquitto_pub -l` match reality - blank lines are
  sent as empty messages. Closes [#1474].
- Free memory in `mosquitto_sub` when quitting without having made a successful
  connection. Closes [#1513].

# Build
- Added `CLIENT_STATIC_LDADD` to makefile builds to allow more libraries to be
  linked when compiling the clients with a static libmosquitto, as required
  for e.g. openssl on some systems.

# Installer
- Fix `mosquitto_rr.exe` not being included in Windows installers. Closes [#1463].

[#1429]: https://github.com/eclipse-mosquitto/mosquitto/issues/1429
[#1432]: https://github.com/eclipse-mosquitto/mosquitto/issues/1432
[#1437]: https://github.com/eclipse-mosquitto/mosquitto/issues/1437
[#1441]: https://github.com/eclipse-mosquitto/mosquitto/issues/1441
[#1442]: https://github.com/eclipse-mosquitto/mosquitto/issues/1442
[#1448]: https://github.com/eclipse-mosquitto/mosquitto/issues/1448
[#1453]: https://github.com/eclipse-mosquitto/mosquitto/issues/1453
[#1459]: https://github.com/eclipse-mosquitto/mosquitto/issues/1459
[#1463]: https://github.com/eclipse-mosquitto/mosquitto/issues/1463
[#1464]: https://github.com/eclipse-mosquitto/mosquitto/issues/1464
[#1473]: https://github.com/eclipse-mosquitto/mosquitto/issues/1473
[#1474]: https://github.com/eclipse-mosquitto/mosquitto/issues/1474
[#1478]: https://github.com/eclipse-mosquitto/mosquitto/issues/1478
[#1489]: https://github.com/eclipse-mosquitto/mosquitto/issues/1489
[#1494]: https://github.com/eclipse-mosquitto/mosquitto/issues/1494
[#1499]: https://github.com/eclipse-mosquitto/mosquitto/issues/1499
[#1513]: https://github.com/eclipse-mosquitto/mosquitto/issues/1513
