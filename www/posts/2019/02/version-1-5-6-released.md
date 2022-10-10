<!--
.. title: Version 1.5.6 released
.. slug: version-1-5-6-released
.. date: 2019-02-08 13:00:00 UTC
.. tags: Security,Releases
.. category:
.. link:
.. description:
.. type: text
-->

Mosquitto 1.5.6 has been released to address three potential security vulnerabilities.

# CVE-2018-12551

If Mosquitto is configured to use a password file for authentication, any
malformed data in the password file will be treated as valid. This typically
means that the malformed data becomes a username and no password. If this
occurs, clients can circumvent authentication and get access to the broker by
using the malformed username. In particular, a blank line will be treated as a
valid empty username. Other security measures are unaffected. **Users who have
only used the `mosquitto_passwd` utility to create and modify their password
files are unaffected by this vulnerability**. Affects version 1.0 to 1.5.5
inclusive.

Patches for older versions are available at <https://mosquitto.org/files/cve/2018-12551>

# CVE-2018-12550

If an ACL file is empty, or has only blank lines or comments, then mosquitto
treats the ACL file as not being defined, which means that no topic access is
denied. Although denying access to all topics is not a useful configuration,
this behaviour is unexpected and could lead to access being incorrectly granted
in some circumstances. Affects versions 1.0 to 1.5.5 inclusive.

Patches for older versions are available at <https://mosquitto.org/files/cve/2018-12550>

# CVE-2018-12546

If a client publishes a retained message to a topic that they have access to,
and then their access to that topic is revoked, the retained message will still
be delivered to future subscribers. This behaviour may be undesirable in some
applications, so a configuration option `check_retain_source` has been
introduced to enforce checking of the retained message source on publish.

Patches for older versions are available at <https://mosquitto.org/files/cve/2018-12546>

# Version 1.5.6 Changes

The list of other fixes addressed in version 1.5.6 is:

## Broker

- Fixed comment handling for config options that have optional arguments.
- Improved documentation around bridge topic remapping.
- Handle mismatched handshakes (e.g. QoS1 PUBLISH with QoS2 reply) properly.
- Fix spaces not being allowed in the bridge `remote_username option`. Closes
  [#1131].
- Allow broker to always restart on Windows when using `log_dest file`. Closes
  [#1080].
- Fix Will not being sent for Websockets clients. Closes [#1143].
- Windows: Fix possible crash when client disconnects. Closes [#1137].
- Fixed durable clients being unable to receive messages when offline, when
  `per_listener_settings` was set to true. Closes [#1081].
- Add log message for the case where a client is disconnected for sending a
  topic with invalid UTF-8. Closes [#1144].

## Library

- Fix TLS connections not working over SOCKS.
- Don't clear SSL context when TLS connection is closed, meaning if a user
  provided an external SSL_CTX they have less chance of leaking references.

## Build

- Fix comparison of boolean values in CMake build. Closes [#1101].
- Fix compilation when openssl deprecated APIs are not available.
  Closes [#1094].
- Man pages can now be built on any system. Closes [#1139].

[#1080]: https://github.com/eclipse/mosquitto/issues/1080
[#1081]: https://github.com/eclipse/mosquitto/issues/1081
[#1094]: https://github.com/eclipse/mosquitto/issues/1094
[#1101]: https://github.com/eclipse/mosquitto/issues/1101
[#1131]: https://github.com/eclipse/mosquitto/issues/1131
[#1137]: https://github.com/eclipse/mosquitto/issues/1137
[#1139]: https://github.com/eclipse/mosquitto/issues/1139
[#1143]: https://github.com/eclipse/mosquitto/issues/1143
[#1144]: https://github.com/eclipse/mosquitto/issues/1144
