<!--
.. title: Version 1.5.7 released
.. slug: version-1-5-7-released
.. date: 2019-02-13 23:50:00 UTC
.. tags: Releases
.. category:
.. link:
.. description:
.. type: text
-->

This is a bugfix release.

## Broker
- Fix build failure when using `WITH_ADNS=yes`
- Ensure that an error occurs if `per_listener_settings true` is given after
  other security options. Closes [#1149].
- Fix `include_dir` not sorting config files before loading. This was partially
  fixed in 1.5 previously.
- Improve documentation around the `include_dir` option. Closes [#1154].
- Fix case where old unreferenced msg_store messages were being saved to the
  persistence file, bloating its size unnecessarily. Closes [#389].

## Library
- Fix `mosquitto_topic_matches_sub()` not returning MOSQ_ERR_INVAL for
  invalid subscriptions like `topic/#abc`. This only affects the return value,
  not the match/no match result, which was already correct.

## Build
- Don't require C99 compiler.
- Add rewritten build test script and remove some build warnings.


[#389]: https://github.com/eclipse-mosquitto/mosquitto/issues/389
[#1149]: https://github.com/eclipse-mosquitto/mosquitto/issues/1149
[#1154]: https://github.com/eclipse-mosquitto/mosquitto/issues/1154
