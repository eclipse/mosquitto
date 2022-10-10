<!--
.. title: Version 2.0.6 released.
.. slug: version-2-0-6-released
.. date: 2021-01-28 12:24:38 UTC
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.0.6 of Mosquitto has been released. This is a bugfix release.

# Broker
- Fix calculation of remaining length parameter for websockets clients that
  send fragmented packets. Closes [#1974].
- Fix potential duplicate Will messages being sent when a will delay interval
  has been set.
- Fix message expiry interval property not being honoured in
  `mosquitto_broker_publish` and `mosquitto_broker_publish_copy`.
- Fix websockets listeners with TLS not responding. Closes [#2020].
- Add notes that libsystemd-dev or similar is needed if building with systemd
  support. Closes [#2019].
- Improve logging in obscure cases when a client disconnects. Closes [#2017].
- Fix reloading of listeners where multiple listeners have been defined with
  the same port but different bind addresses. Closes [#2029].
- Fix `message_size_limit` not applying to the Will payload. Closes [#2022].
- The error topic-alias-invalid was being sent if an MQTT v5 client published
  a message with empty topic and topic alias set, but the topic alias hadn't
  already been configured on the broker. This has been fixed to send a
  protocol error, as per section 3.3.4 of the specification.
- Note in the man pages that SIGHUP reloads TLS certificates. Closes [#2037].
- Fix bridges not always connecting on Windows. Closes [#2043].

# Apps
- Allow command line arguments to override config file options in
  mosquitto_ctrl. Closes [#2010].
- mosquitto_ctrl: produce an error when requesting a new password if both
  attempts do not match. Closes [#2011].

# Build
- Fix cmake builds using `WITH_CJSON=no` not working if cJSON not found.
  Closes [#2026].

# Other
- The SPDX identifiers for EDL-1.0 have been changed to BSD-3-Clause as per
  The Eclipse legal documentation generator. The licenses are identical.

[#1974]: https://github.com/eclipse/mosquitto/issues/1974
[#2010]: https://github.com/eclipse/mosquitto/issues/2010
[#2011]: https://github.com/eclipse/mosquitto/issues/2011
[#2017]: https://github.com/eclipse/mosquitto/issues/2017
[#2019]: https://github.com/eclipse/mosquitto/issues/2019
[#2020]: https://github.com/eclipse/mosquitto/issues/2020
[#2022]: https://github.com/eclipse/mosquitto/issues/2022
[#2026]: https://github.com/eclipse/mosquitto/issues/2026
[#2029]: https://github.com/eclipse/mosquitto/issues/2029
[#2037]: https://github.com/eclipse/mosquitto/issues/2037
[#2043]: https://github.com/eclipse/mosquitto/issues/2043
