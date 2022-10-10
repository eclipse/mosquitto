<!--
.. title: Version 2.0.0 released.
.. slug: version-2-0-0-released
.. date: 2020-12-03 16:00:00 UTC+00:00
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

The Mosquitto project is happy to announce the release of version 2.0! This is
a big change with breaking behaviour changes in the broker. Users, packages and
plugin authors should read [migrating from 1.x to 2.0] to help with the
changes.

# Noteworthy changes

Mosquitto is now more secure by default and requires users to take an active
decision in how they configure security on their broker, instead of possibly
relying on the older very permissive behaviour, as well as dropping privileged
access more quickly. More details are in [migrating from 1.x to 2.0].

A new plugin interface has been introduced which goes beyond the existing
authentication and access control plugin interface to offer more plugin
capabilities, whilst being easier to develop for and easier to extend. More
details will follow. Existing plugins are still supported, although plugin
authors should look at [migrating from 1.x to 2.0] to ensure their plugins
remain compatible when compiled against Mosquitto 2.0 headers.

A new plugin has been introduced to provide client, group, and role based
authentication and access control. The plugin configuration is managed over
special topics and can be updated on the fly. It provides a flexible and
straightforward means of configuring access to your broker. For more
information, see [Dynamic Security plugin].

The broker performance has been improved, particularly for higher numbers of
clients. We plan to run show some benchmarks to show the improvement.

A new utility, `mosquitto_ctrl` has been added for controlling aspects of a
running broker. At the present this is limited to controlling the dynamic
security plugin, but will be extended to other features in later releases.

Bridges now support MQTT v5.

The mosquitto command line clients have received a variety of small
improvements. mosquitto_sub can now format its output in fixed column widths,
for example, and filter its output randomly so you can keep an eye on the
overall behaviour of a topic without having to see every message, for example.

# Breaking changes
- When the Mosquitto broker is run without configuring any listeners it will
  now bind to the loopback interfaces 127.0.0.1 and/or ::1. This means that
  only connections from the local host will be possible.

  Running the broker as `mosquitto` or `mosquitto -p 1883` will bind to the
  loopback interface.

  Running the broker with a configuration file with no listeners configured
  will bind to the loopback interface with port 1883.

  Running the broker with a listener defined will bind by default to `0.0.0.0`
  / `::` and so will be accessible from any interface. It is still possible to
  bind to a specific address/interface.

  If the broker is run as `mosquitto -c mosquitto.conf -p 1884`, and a
  listener is defined in the configuration file, then the port defined on the
  command line will be IGNORED, and no listener configured for it.
- All listeners now default to `allow_anonymous false` unless explicitly set
  to true in the configuration file. This means that when configuring a
  listener the user must either configure an authentication and access control
  method, or set `allow_anonymous true`. When the broker is run without a
  configured listener, and so binds to the loopback interface, anonymous
  connections are allowed.
- If Mosquitto is run on as root on a unix like system, it will attempt to
  drop privileges as soon as the configuration file has been read. This is in
  contrast to the previous behaviour where elevated privileges were only
  dropped after listeners had been started (and hence TLS certificates loaded)
  and logging had been started. The change means that clients will never be
  able to connect to the broker when it is running as root, unless the user
  explicitly sets it to run as root, which is not advised. It also means that
  all locations that the broker needs to access must be available to the
  unprivileged user. In particular those people using TLS certificates from
  Lets Encrypt will need to do something to allow Mosquitto to access
  those certificates. An example deploy renewal hook script to help with this
  is at `misc/letsencrypt/mosquitto-copy.sh`.
  The user that Mosquitto will change to are the one provided in the
  configuration, `mosquitto`, or `nobody`, in order of availability.
- The `pid_file` option will now always attempt to write a pid file,
  regardless of whether the `-d` argument is used when running the broker.
- The `tls_version` option now defines the *minimum* TLS protocol version to
  be used, rather than the exact version. Closes [#1258].
- The `max_queued_messages` option has been increased from 100 to 1000 by
  default, and now also applies to QoS 0 messages, when a client is connected.
- The mosquitto_sub, mosquitto_pub, and mosquitto_rr clients will now load
  OS provided CA certificates by default if `-L mqtts://...` is used, or if
  the port is set to 8883 and no other CA certificates are loaded.
- Minimum support libwebsockets version is now 2.4.0


# Broker features
- New plugin interface which is more flexible, easier to develop for and
  easier to extend.
- New dynamic security plugin, which allows clients, groups, and roles to be
  defined and updated as the broker is running.
- Performance improvements, particularly for higher numbers of clients.
- When running as root, if dropping privileges to the "mosquitto" user fails,
  then try "nobody" instead. This reduces the burden on users installing
  Mosquitto themselves.
- Add support for Unix domain socket listeners.
- Add `bridge_outgoing_retain` option, to allow outgoing messages from a
  bridge to have the retain bit completely disabled, which is useful when
  bridging to e.g. Amazon or Google.
- Add support for MQTT v5 bridges to handle the "retain-available" property
  being false.
- Allow MQTT v5.0 outgoing bridges to fall back to MQTT v3.1.1 if connecting
  to a v3.x only broker.
- DLT logging is now configurable at runtime with `log_dest dlt`.
  Closes [#1735].
- Add `mosquitto_plugin_publish()` function, which can be used by plugins to
  publish messages.
- Add `mosquitto_client_protocol_version()` function which can be used by
  plugins to determine which version of MQTT a client has connected with.
- Add `mosquitto_kick_client_by_clientid()` and `mosquitto_kick_client_by_username()`
  functions, which can be used by plugins to disconnect clients.
- Add support for handling $CONTROL/ topics in plugins.
- Add support for PBKDF2-SHA512 password hashing.
- Enabling certificate based TLS encryption is now through certfile and
  keyfile, not capath or cafile.
- Added support for controlling UNSUBSCRIBE calls in v5 plugin ACL checks.
- Add "deny" acl type. Closes [#1611].
- The broker now sends the receive-maximum property for MQTT v5 CONNACKs.
- Add the `bridge_max_packet_size` option. Closes [#265].
- Add the `bridge_bind_address` option. Closes [#1311].
- TLS certificates for the server are now reloaded on SIGHUP.
- Default for max_queued_messages has been changed to 1000.
- Add `ciphers_tls1.3` option, to allow setting TLS v1.3 ciphersuites.
  Closes [#1825].
- Bridges now obey MQTT v5 server-keepalive.
- Add bridge support for the MQTT v5 maximum-qos property.
- Log client port on new connections. Closes [#1911].

# Broker fixes
- Send DISCONNECT with `malformed-packet` reason code on invalid PUBLISH,
  SUBSCRIBE, and UNSUBSCRIBE packets.
- Document that X509_free() must be called after using
  mosquitto_client_certificate(). Closes [#1842].
- Fix listener not being reassociated with client when reloading a persistence
  file and `per_listener_settings true` is set and the client did not set a
  username. Closes [#1891].
- Fix bridge sock not being removed from sock hash on error. Closes [#1897].
- mosquitto_password now forbids the : character. Closes [#1833].
- Fix `log_timestamp_format` not applying to `log_dest topic`. Closes [#1862].
- Fix crash on Windows if loading a plugin fails. Closes [#1866].
- Fix file logging on Windows. Closes [#1880].
- Report an error if the config file is set to a directory. Closes [#1814].
- Fix bridges incorrectly setting Wills to manage remote notifications when
  `notifications_local_only` was set true. Closes [#1902].

# Client library features
- Client no longer generates random client ids for v3.1.1 clients, these are
  now expected to be generated on the broker. This matches the behaviour for
  v5 clients. Closes [#291].
- Add support for connecting to brokers through Unix domain sockets.
- Add `mosquitto_property_identifier()`, for retrieving the identifier integer
  for a property.
- Add `mosquitto_property_identifier_to_string()` for converting a property
  identifier integer to the corresponding property name string.
- Add `mosquitto_property_next()` to retrieve the next property in a list, for
  iterating over property lists.
- mosquitto_pub now handles the MQTT v5 retain-available property by never
  setting the retain bit.
- Added MOSQ_OPT_TCP_NODELAY, to allow disabling Nagle's algorithm on client
  sockets. Closes [#1526].
- Add `mosquitto_ssl_get()` to allow clients to access their SSL structure and
  perform additional verification.
- Add MOSQ_OPT_BIND_ADDRESS to allow setting of a bind address independently
  of the `mosquitto_connect*()` call.
- Add `MOSQ_OPT_TLS_USE_OS_CERTS` option, to instruct the client to load and
  trust OS provided CA certificates for use with TLS connections.

# Client library fixes
- Fix send quota being incorrecly reset on reconnect. Closes [#1822].
- Don't use logging until log mutex is initialised. Closes [#1819].
- Fix missing mach/mach_time.h header on OS X. Closes [#1831].
- Fix connect properties not being sent when the client automatically
  reconnects. Closes [#1846].

# Client features
- Add timeout return code (27) for `mosquitto_sub -W <secs>` and
  `mosquitto_rr -W <secs>`. Closes [#275].
- Add support for connecting to brokers through Unix domain sockets with the
  `--unix` argument.
- Use cJSON library for producing JSON output, where available. Closes [#1222].
- Add support for outputting MQTT v5 property information to mosquitto_sub/rr
  JSON output. Closes [#1416].
- Add `--pretty` option to mosquitto_sub/rr for formatted/unformatted JSON
  output.
- Add support for v5 property printing to mosquitto_sub/rr in non-JSON mode.
  Closes [#1416].
- Add `--nodelay` to all clients to allow them to use the MOSQ_OPT_TCP_NODELAY
  option.
- Add `-x` to all clients to all the session-expiry-interval property to be
  easily set for MQTT v5 clients.
- Add `--random-filter` to mosquitto_sub, to allow only a certain proportion
  of received messages to be printed.
- mosquitto_sub %j and %J timestamps are now in a ISO 8601 compatible format.
- mosquitto_sub now supports extra format specifiers for field width and
  precision for some parameters.
- Add `--version` for all clients.
- All clients now load OS provided CA certificates if used with `-L
  mqtts://...`, or if port is set to 8883 and no other CA certificates are
  used. Closes [#1824].
- Add the `--tls-use-os-certs` option to all clients.

# Client fixes
- mosquitto_sub will now exit if all subscriptions were denied.
- mosquitto_pub now sends 0 length files without an error when using `-f`.
- Fix description of `-e` and `-t` arguments in mosquitto_rr. Closes [#1881].
- mosquitto_sub will now quit with an error if the %U option is used on
  Windows, rather than just quitting. Closes [#1908].

[migrating from 1.x to 2.0]:/documentation/migrating-to-2-0/
[#265]: https://github.com/eclipse/mosquitto/issues/265
[#275]: https://github.com/eclipse/mosquitto/issues/275
[#291]: https://github.com/eclipse/mosquitto/issues/291
[#1222]: https://github.com/eclipse/mosquitto/issues/1222
[#1258]: https://github.com/eclipse/mosquitto/issues/1258
[#1311]: https://github.com/eclipse/mosquitto/issues/1311
[#1416]: https://github.com/eclipse/mosquitto/issues/1416
[#1526]: https://github.com/eclipse/mosquitto/issues/1526
[#1611]: https://github.com/eclipse/mosquitto/issues/1611
[#1735]: https://github.com/eclipse/mosquitto/issues/1735
[#1814]: https://github.com/eclipse/mosquitto/issues/1814
[#1819]: https://github.com/eclipse/mosquitto/issues/1819
[#1822]: https://github.com/eclipse/mosquitto/issues/1822
[#1824]: https://github.com/eclipse/mosquitto/issues/1824
[#1825]: https://github.com/eclipse/mosquitto/issues/1825
[#1831]: https://github.com/eclipse/mosquitto/issues/1831
[#1833]: https://github.com/eclipse/mosquitto/issues/1833
[#1842]: https://github.com/eclipse/mosquitto/issues/1842
[#1846]: https://github.com/eclipse/mosquitto/issues/1846
[#1862]: https://github.com/eclipse/mosquitto/issues/1862
[#1866]: https://github.com/eclipse/mosquitto/issues/1866
[#1880]: https://github.com/eclipse/mosquitto/issues/1880
[#1881]: https://github.com/eclipse/mosquitto/issues/1881
[#1891]: https://github.com/eclipse/mosquitto/issues/1891
[#1897]: https://github.com/eclipse/mosquitto/issues/1897
[#1902]: https://github.com/eclipse/mosquitto/issues/1902
[#1908]: https://github.com/eclipse/mosquitto/issues/1908
[#1911]: https://github.com/eclipse/mosquitto/issues/1911
