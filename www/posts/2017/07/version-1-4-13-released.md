<!--
.. title: Version 1.4.13 released
.. slug: version-1-4-13-released
.. date: 2017-07-05 10:47:23
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

This is a bugfix and security release.

# Security

 * Fix [CVE-2017-9868].
   The persistence file was readable by all local users, potentially allowing
   sensitive information to be leaked.  This can also be fixed
   administratively, by restricting access to the directory in which the
   persistence file is stored.

# Broker

 * Fix for poor websockets performance.
 * Fix lazy bridges not timing out for `idle_timeout`. Closes [#417].
 * Fix problems with large retained messages over websockets. Closes [#427].
 * Set persistence file to only be readable by owner, except on Windows. Closes
   [#468].
 * Fix CONNECT check for reserved=0, as per MQTT v3.1.1 check MQTT-3.1.2-3.
 * When the broker stop, wills for any connected clients are now "sent". Closes
   [#477].
 * Auth plugins can be configured to disable the check for +# in
   usernames/client ids with the `auth_plugin_deny_special_chars` option.
   Partially closes [#462].
 * Restrictions for [CVE-2017-7650] have been relaxed - '/' is allowed in
   usernames/client ids.
 * Remainder of fix for [#462].

# Clients

 * Don't use / in auto-generated client ids.

[CVE-2017-7650]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7650
[CVE-2017-9868]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9868
[#417]: https://github.com/eclipse-mosquitto/mosquitto/issues/417
[#427]: https://github.com/eclipse-mosquitto/mosquitto/issues/427
[#462]: https://github.com/eclipse-mosquitto/mosquitto/issues/462
[#468]: https://github.com/eclipse-mosquitto/mosquitto/issues/468
[#477]: https://github.com/eclipse-mosquitto/mosquitto/issues/477
