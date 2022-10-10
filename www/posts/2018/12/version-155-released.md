<!--
.. title: Version 1.5.5 released
.. slug: version-155-released
.. date: 2018-12-11 15:57:18 UTC+00:00
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

This is a bugfix and security release.

# Version 1.5.5 changes

## Security
- If `per_listener_settings` is set to true, then the `acl_file` setting was
  ignored for the "default listener" only. This has been fixed. This does not
  affect any listeners defined with the `listener` option. Closes [#1073].
  This is now tracked as [CVE-2018-20145].

## Broker
- Add `socket_domain` option to allow listeners to disable IPv6 support.
  This is required to work around a problem in libwebsockets that means
  sockets only listen on IPv6 by default if IPv6 support is compiled in.
  Closes [#1004].
- When using ADNS, don't ask for all network protocols when connecting,
  because this can lead to confusing "Protocol not supported" errors if the
  network is down. Closes [#1062].
- Fix outgoing retained messages not being sent by bridges on initial
  connection. Closes [#1040].
- Don't reload `auth_opt_` options on reload, to match the behaviour of the
  other plugin options. Closes [#1068].
- Print message on error when installing/uninstalling as a Windows service.
- All non-error connect/disconnect messages are controlled by the
  `connection_messages` option. Closes [#772]. Closes [#613]. Closes [#537].

## Library
- Fix reconnect delay backoff behaviour. Closes [#1027].
- Don't call `on_disconnect()` twice if keepalive tests fail. Closes [#1067].

## Client
- Always print leading zeros in `mosquitto_sub` when output format is hex.
  Closes [#1066].

## Build
- Fix building where TLS-PSK is not available. Closes [#68].


[CVE-2018-20145]: https://nvd.nist.gov/vuln/detail/CVE-2018-20145
[#68]: https://github.com/eclipse/mosquitto/issues/68
[#537]: https://github.com/eclipse/mosquitto/issues/537
[#613]: https://github.com/eclipse/mosquitto/issues/613
[#772]: https://github.com/eclipse/mosquitto/issues/772
[#1004]: https://github.com/eclipse/mosquitto/issues/1004
[#1027]: https://github.com/eclipse/mosquitto/issues/1027
[#1040]: https://github.com/eclipse/mosquitto/issues/1040
[#1062]: https://github.com/eclipse/mosquitto/issues/1062
[#1066]: https://github.com/eclipse/mosquitto/issues/1066
[#1067]: https://github.com/eclipse/mosquitto/issues/1067
[#1068]: https://github.com/eclipse/mosquitto/issues/1068
[#1073]: https://github.com/eclipse/mosquitto/issues/1073
