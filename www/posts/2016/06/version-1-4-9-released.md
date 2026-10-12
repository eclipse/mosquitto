<!--
.. title: Version 1.4.9 released
.. slug: version-1-4-9-released
.. date: 2016-06-03 11:00:17
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

This is a bugfix release.

# Broker

 * Ensure websockets clients that previously connected with clean session set
   to false have their queued messages delivered immediately on reconnecting.
   Closes [#5].
 * Reconnecting client with clean session set to false doesn't start with mid=1
   again.
 * Will topic isn't truncated by one byte when using a `mount_point` any more.
 * Network errors are printed correctly on Windows.
 * Fix incorrect $SYS heap memory reporting when using ACLs.
 * Bridge config parameters couldn't contain a space, this has been fixed.
   Closes [#150].
 * Fix saving of persistence messages that start with a '/'. Closes [#151].
 * Fix reconnecting for bridges that use TLS on Windows. Closes [#154].
 * Broker and bridges can now cope with unknown incoming PUBACK, PUBREC,
   PUBREL, PUBCOMP without disconnecting. Closes [#57].
 * Fix websockets listeners not being able to bind to an IP address. Closes
   [#170].
 * mosquitto_passwd utility now correctly deals with unknown command line
   arguments in all cases. Closes [#169].
 * Fix publishing of $SYS/broker/clients/maximum
 * Fix order of #includes in lib/send_mosq.c to ensure struct mosquitto doesn't
   differ between source files when websockets is being used. Closes [#180].
 * Fix possible rare crash when writing out persistence file and a client has
   incomplete messages inflight that it has been denied the right to publish.

# Client library

 * Fix the case where a message received just before the keepalive timer
   expired would cause the client to miss the keepalive timer.
 * Return value of pthread_create is now checked.
 * _mosquitto_destroy should not cancel threads that weren't created by
   libmosquitto. Closes [#166].
 * Clients can now cope with unknown incoming PUBACK, PUBREC, PUBREL, PUBCOMP
   without disconnecting. Closes [#57].
 * Fix mosquitto_topic_matches_sub() reporting matches on some invalid
   subscriptions.

# Clients

 * Handle some unchecked malloc() calls. Closes [#1].

# Build

 * Fix string quoting in CMakeLists.txt. Closes [#4].
 * Fix building on Visual Studio 2015. Closes [#136].

[#1]: https://github.com/eclipse-mosquitto/mosquitto/issues/1
[#4]: https://github.com/eclipse-mosquitto/mosquitto/issues/4
[#5]: https://github.com/eclipse-mosquitto/mosquitto/issues/5
[#57]: https://github.com/eclipse-mosquitto/mosquitto/issues/57
[#136]: https://github.com/eclipse-mosquitto/mosquitto/issues/136
[#150]: https://github.com/eclipse-mosquitto/mosquitto/issues/150
[#151]: https://github.com/eclipse-mosquitto/mosquitto/issues/151
[#154]: https://github.com/eclipse-mosquitto/mosquitto/issues/154
[#166]: https://github.com/eclipse-mosquitto/mosquitto/issues/166
[#169]: https://github.com/eclipse-mosquitto/mosquitto/issues/169
[#170]: https://github.com/eclipse-mosquitto/mosquitto/issues/170
[#180]: https://github.com/eclipse-mosquitto/mosquitto/issues/180
