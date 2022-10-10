<!--
.. title: Version 2.0.8 released.
.. slug: version-2-0-8-released
.. date: 2021-02-25 17:19:38 UTC
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

Version 2.0.8 of Mosquitto has been released. This is a bugfix release.

# Broker
- Fix incorrect datatypes in `struct mosquitto_evt_tick`. This changes the
  size and offset of two of the members of this struct, and changes the size
  of the struct. This is an ABI break, but is considered to be acceptable
  because plugins should never be allocating their own instance of this
  struct, and currently none of the struct members are used for anything, so a
  plugin should not be accessing them. It would also be safe to read/write
  from the existing struct parameters.
- Give compile time warning if libwebsockets compiled without external poll
  support. Closes [#2060].
- Fix memory tracking not being available on FreeBSD or macOS. Closes [#2096].

# Client library
- Fix `mosquitto_{pub|sub}_topic_check()` functions not returning `MOSQ_ERR_INVAL`
  on topic == NULL.

# Clients
- Fix possible loss of data in `mosquitto_pub -l` when sending multiple long
  lines. Closes [#2078].

# Build
- Provide a mechanism for Docker users to run a broker that doesn't use
  authentication, without having to provide their own configuration file.
  Closes [#2040].

[#2040]: https://github.com/eclipse/mosquitto/issues/2040
[#2060]: https://github.com/eclipse/mosquitto/issues/2060
[#2078]: https://github.com/eclipse/mosquitto/issues/2078
[#2096]: https://github.com/eclipse/mosquitto/issues/2096
