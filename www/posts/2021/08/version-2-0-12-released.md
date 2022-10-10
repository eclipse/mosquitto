<!--
.. title: Version 2.0.12 released.
.. slug: version-2-0-12-released
.. date: 2021-08-31 17:16:38 UTC+1
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Versions 2.0.12 of Mosquitto has been released. This is a security
and bugfix release.

# Security
- An MQTT v5 client connecting with a large number of user-property properties
  could cause excessive CPU usage, leading to a loss of performance and
  possible denial of service. This has been fixed.
- Fix `max_keepalive` not applying to MQTT v3.1.1 and v3.1 connections.
  These clients are now rejected if their keepalive value exceeds
  max_keepalive. This option allows [CVE-2020-13849], which is for the MQTT
  v3.1.1 protocol itself rather than an implementation, to be addressed.
- Using certain listener related configuration options e.g. `cafile`, that
  apply to the default listener without defining any listener would cause a
  remotely accessible listener to be opened that was not confined to the local
  machine but did have anonymous access enabled, contrary to the
  documentation. This has been fixed. Closes [#2283].
- [CVE-2021-34434]: If a plugin had granted ACL subscription access to a
  durable/non-clean-session client, then removed that access, the client would
  keep its existing subscription. This has been fixed.
- Incoming QoS 2 messages that had not completed the QoS flow were not being
  checked for ACL access when a clean session=False client was reconnecting.
  This has been fixed.

# Broker
- Fix possible out of bounds memory reads when reading a corrupt/crafted
  configuration file. Unless your configuration file is writable by untrusted
  users this is not a risk. Closes [#567213].
- Fix `max_connections` option not being correctly counted.
- Fix TLS certificates and TLS-PSK not being able to be configured at the same
  time.
- Disable TLS v1.3 when using TLS-PSK, because it isn't correctly configured.
- Fix `max_keepalive` not applying to MQTT v3.1.1 and v3.1 connections.
  These clients are now rejected if their keepalive value exceeds
  `max_keepalive`. This option allows CVE-2020-13849, which is for the MQTT
  v3.1.1 protocol itself rather than an implementation, to be addressed.
- Fix broker not quiting if e.g. the `password_file` is specified as a
  directory. Closes [#2241].
- Fix listener `mount_point` not being removed on outgoing messages.
  Closes [#2244].
- Strict protocol compliance fixes, plus test suite.
- Fix $share subscriptions not being recovered for durable clients that
  reconnect.
- Update plugin configuration documentation. Closes [#2286].

# Client library
- If a client uses TLS-PSK then force the default cipher list to use "PSK"
  ciphers only. This means that a client connecting to a broker configured
  with x509 certificates only will now fail. Prior to this, the client would
  connect successfully without verifying certificates, because they were not
  configured.
- Disable TLS v1.3 when using TLS-PSK, because it isn't correctly configured.
- Threaded mode is deconfigured when the `mosquitto_loop_start()` thread ends,
  which allows `mosquitto_loop_start()` to be called again. Closes [#2242].
- Fix `MOSQ_OPT_SSL_CTX` not being able to be set to NULL. Closes [#2289].
- Fix reconnecting failing when `MOSQ_OPT_TLS_USE_OS_CERTS` was in use, but none
  of `capath`, `cafile`, `psk`, nor `MOSQ_OPT_SSL_CTX` were set, and
  `MOSQ_OPT_SSL_CTX_WITH_DEFAULTS` was set to the default value of true.
  Closes [#2288].

# Apps
- Fix `mosquitto_ctrl dynsec setDefaultACLAccess` command not working.

# Clients
- `mosquitto_sub` and `mosquitto_rr` now open stdout in binary mode on Windows
  so binary payloads are not modified when printing.
- Document TLS certificate behaviour when using `-p 8883`.

# Build
- Fix installation using `WITH_TLS=no`. Closes [#2281].
- Fix builds with libressl 3.4.0. Closes [#2198].
- Remove some unnecessary code guards related to libressl.
- Fix printf format build warning on MIPS. Closes [#2271].

[#2198]: https://github.com/eclipse/mosquitto/issues/2198
[#2241]: https://github.com/eclipse/mosquitto/issues/2241
[#2242]: https://github.com/eclipse/mosquitto/issues/2242
[#2244]: https://github.com/eclipse/mosquitto/issues/2244
[#2271]: https://github.com/eclipse/mosquitto/issues/2271
[#2281]: https://github.com/eclipse/mosquitto/issues/2281
[#2286]: https://github.com/eclipse/mosquitto/issues/2286
[#2288]: https://github.com/eclipse/mosquitto/issues/2288
[#2289]: https://github.com/eclipse/mosquitto/issues/2289
[#567213]: https://bugs.eclipse.org/bugs/show_bug.cgi?id=567213
[CVE-2020-13849]: https://nvd.nist.gov/vuln/detail/CVE-2020-13849
[CVE-2021-34434]: https://nvd.nist.gov/vuln/detail/CVE-2021-34434
