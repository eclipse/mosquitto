<!--
.. title: Version 2.0.16 released.
.. slug: version-2-0-16-released
.. date: 2023-08-16 12:57:38 UTC+1
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.0.16 of Mosquitto has been released. This is a security
and bugfix release.

# Security
- [CVE-2023-28366]: Fix memory leak in broker when clients send multiple QoS 2
  messages with the same message ID, but then never respond to the PUBREC
  commands.
- [CVE-2023-0809]: Fix excessive memory being allocated based on malicious
  initial packets that are not CONNECT packets.
- [CVE-2023-3592]: Fix memory leak when clients send v5 CONNECT packets with a
  will message that contains invalid property types.
- Broker will now reject Will messages that attempt to publish to $CONTROL/.
- Broker now validates usernames provided in a TLS certificate or TLS-PSK
  identity are valid UTF-8.
- Fix potential crash when loading invalid persistence file.
- Library will no longer allow single level wildcard certificates, e.g. *.com

# Broker
- Fix $SYS messages being expired after 60 seconds and hence unchanged values
  disappearing.
- Fix some retained topic memory not being cleared immediately after used.
- Fix error handling related to the `bind_interface` option.
- Fix std* files not being redirected when daemonising, when built with
  assertions removed. Closes [#2708].
- Fix default settings incorrectly allowing TLS v1.1. Closes [#2722].
- Use line buffered mode for stdout. Closes #2354. Closes [#2749].
- Fix bridges with non-matching cleansession/local_cleansession being expired
  on start after restoring from persistence. Closes [#2634].
- Fix connections being limited to 2048 on Windows. The limit is now 8192,
  where supported. Closes [#2732].
- Broker will log warnings if sensitive files are world readable/writable, or
  if the owner/group is not the same as the user/group the broker is running
  as. In future versions the broker will refuse to open these files.
- mosquitto_memcmp_const is now more constant time.
- Only register with DLT if DLT logging is enabled.
- Fix any possible case where a json string might be incorrectly loaded. This
  could have caused a crash if a textname or textdescription field of a role was
  not a string, when loading the dynsec config from file only.
- Dynsec plugin will not allow duplicate clients/groups/roles when loading
  config from file, which matches the behaviour for when creating them.
- Fix heap overflow when reading corrupt config with "log_dest file".

# Client library
- Use CLOCK_BOOTTIME when available, to keep track of time. This solves the
  problem of the client OS sleeping and the client hence not being able to
  calculate the actual time for keepalive purposes. Closes [#2760].
- Fix default settings incorrectly allowing TLS v1.1. Closes [#2722].
- Fix high CPU use on slow TLS connect. Closes [#2794].

# Clients
- Fix incorrect topic-alias property value in mosquitto_sub json output.
- Fix confusing message on TLS certificate verification. Closes [#2746].

# Apps
- mosquitto_passwd uses mkstemp() for backup files.
- `mosquitto_ctrl dynsec init` will refuse to overwrite an existing file,
  without a race-condition.

[CVE-2023-0809]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0809
[CVE-2023-28366]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27366
[CVE-2023-3592]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-3592
[#2354]: https://github.com/eclipse-mosquitto/mosquitto/issues/2354
[#2634]: https://github.com/eclipse-mosquitto/mosquitto/issues/2634
[#2708]: https://github.com/eclipse-mosquitto/mosquitto/issues/2708
[#2722]: https://github.com/eclipse-mosquitto/mosquitto/issues/2722
[#2722]: https://github.com/eclipse-mosquitto/mosquitto/issues/2722
[#2732]: https://github.com/eclipse-mosquitto/mosquitto/issues/2732
[#2746]: https://github.com/eclipse-mosquitto/mosquitto/issues/2746
[#2749]: https://github.com/eclipse-mosquitto/mosquitto/issues/2749
[#2760]: https://github.com/eclipse-mosquitto/mosquitto/issues/2760
[#2794]: https://github.com/eclipse-mosquitto/mosquitto/issues/2794
[#1488]: https://github.com/eclipse-mosquitto/mosquitto/issues/1488

