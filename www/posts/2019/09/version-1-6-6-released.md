<!--
.. title: Version 1.6.6 released
.. slug: version-1-6-6-released
.. date: 2018-09-27 10:36:19 UTC+01:00
.. tags: Security,Releases
.. category:
.. link:
.. description:
.. type: text
-->

Mosquitto 1.6.6 and 1.5.9 have been released to address two security vulnerabilities.

Titles and links will be updated once the CVE numbers are assigned.

# CVE-2019-11779

A vulnerability exists in Mosquitto versions 1.5 to 1.6.5 inclusive, known as
[CVE-2019-11779].

If a client sends a SUBSCRIBE packet containing a topic that consists of
approximately 65400 or more '/' characters, i.e. the topic hierarchy separator,
then a stack overflow will occur.

The issue is fixed in Mosquitto 1.6.6 and 1.5.9. Patches for older versions are
available at <https://mosquitto.org/files/cve/2019-11779>

The fix addresses the problem by restricting the allowed number of topic
hierarchy levels to 200. An alternative fix is to increase the size of the
stack by a small amount.

# CVE-2019-11778

A vulnerability exists in Mosquitto version 1.6 to 1.6.4 inclusive, known as
[CVE-2019-11778]

If an MQTT v5 client connects to Mosquitto, sets a last will and testament,
sets a will delay interval, sets a session expiry interval, and the will delay
interval is set longer than the session expiry interval, then a use after free
error occurs, which has the potential to cause a crash in some situations.

The issue is fixed in Mosquitto 1.6.5. Patches for older versions are available
at <https://mosquitto.org/files/cve/2019-11778>

# Version 1.6.6 Changes

The complete list of fixes addressed in version 1.6.6 is:

## Security

* Restrict topic hierarchy to 200 levels to prevent possible stack overflow.
  Closes [#1412].

## Broker
* Restrict topic hierarchy to 200 levels to prevent possible stack overflow.
  Closes [#1412].
* `mosquitto_passwd` now returns 1 when attempting to update a user that does
  not exist. Closes [#1414].

[CVE-2019-11778]: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11778
[CVE-2019-11779]: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11779
[#1412]: https://github.com/eclipse-mosquitto/mosquitto/issues/1412
[#1414]: https://github.com/eclipse-mosquitto/mosquitto/issues/1414
