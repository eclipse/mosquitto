<!--
.. title: Version 2.0.20 released.
.. slug: version-2-0-20-released
.. date: 2024-10-16 17:11:38 UTC+1
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.0.20 of Mosquitto has been released. This is a bugfix release.

# Broker
- Fix QoS 1 / QoS 2 publish incorrectly returning "no subscribers".
  Closes #3128.
- Open files with appropriate access on Windows. Closes #3119.
- Don't allow invalid response topic values.
- Fix some strict protocol compliance issues. Closes #3052.

# Client library
- Fix cmake build on OS X. Closes #3125.

# Build
- Fix build on NetBSD

[#3052]: https://github.com/eclipse-mosquitto/mosquitto/issues/3052
[#3119]: https://github.com/eclipse-mosquitto/mosquitto/issues/3119
[#3125]: https://github.com/eclipse-mosquitto/mosquitto/issues/3125
[#3128]: https://github.com/eclipse-mosquitto/mosquitto/issues/3128
