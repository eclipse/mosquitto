<!--
.. title: Version 1.6.9 released.
.. slug: version-1-6-9-released
.. date: 2020-02-20 23:15:13 UTC+00:00
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Mosquitto 1.6.9 has been released, this is a bugfix release.

# Broker
- Fix session expiry with very large expiry intervals. Closes [#1525].
- Check ACL patterns for validity when loading. Closes [#1539].
- Use presence of password file as indicator for whether username checks
  should take place, not whether usernames are defined in the password file.
  Closes [#1545].
- Strip whitespace from end of config file string options. Closes [#1566].
- Satisfy valgrind when exiting on error due to not being able to open a
  listening socket, by calling freeaddrinfo. Closes [#1565].
- Fix `config->user` not being freed on exit. Closes [#1564].
- Fix trailing whitespace not being trimmed on acl users. Closes [#1539].
- Fix `bind_interface` not working for the default listener. Closes [#1533].
- Improve password file parsing in the broker and `mosquitto_passwd`. Closes [#1584].
- Print OpenSSL errors in more situations, like when loading certificates
  fails. Closes [#1552].
- Fix `mosquitto_client_protocol()` returning incorrect values.

# Client library
- Set minimum keepalive argument to `mosquitto_connect*()` to be 5 seconds.
  Closes [#1550].
- Fix `mosquitto_topic_matches_sub()` not returning `MOSQ_ERR_INVAL` if the
  topic contains a wildcard. Closes [#1589].

# Clients
- Fix `--remove-retained` not obeying the `-T` option for filtering out
  topics. Closes [#1585].
- Default behaviour for v5 clients using `-c` is now to use infinite length
  sessions, as with v3 clients. Closes [#1546].

[#1525]: https://github.com/eclipse-mosquitto/mosquitto/issues/1525
[#1533]: https://github.com/eclipse-mosquitto/mosquitto/issues/1533
[#1539]: https://github.com/eclipse-mosquitto/mosquitto/issues/1539
[#1539]: https://github.com/eclipse-mosquitto/mosquitto/issues/1539
[#1545]: https://github.com/eclipse-mosquitto/mosquitto/issues/1545
[#1546]: https://github.com/eclipse-mosquitto/mosquitto/issues/1546
[#1550]: https://github.com/eclipse-mosquitto/mosquitto/issues/1550
[#1552]: https://github.com/eclipse-mosquitto/mosquitto/issues/1552
[#1564]: https://github.com/eclipse-mosquitto/mosquitto/issues/1564
[#1565]: https://github.com/eclipse-mosquitto/mosquitto/issues/1565
[#1566]: https://github.com/eclipse-mosquitto/mosquitto/issues/1566
[#1584]: https://github.com/eclipse-mosquitto/mosquitto/issues/1584
[#1585]: https://github.com/eclipse-mosquitto/mosquitto/issues/1585
[#1589]: https://github.com/eclipse-mosquitto/mosquitto/issues/1589
