<!--
.. title: MQTT 5 progress
.. slug: mqtt5-progress
.. date: 2018-11-29 21:33:29 UTC+00:00
.. tags: MQTT5
.. category:
.. link:
.. description:
.. type: text
-->

Development of support for MQTT 5 is ongoing and making good progress, but has
been substantially delayed due to other non-Mosquitto work having to take
priority.

It is possible to test the current state of MQTT 5 support by using the `mqtt5`
branch of the [repository]. Please note that this is very much a work in
progress, so parts are incomplete and interfaces may yet change. The client
library in particular has had to have an increase in functions available in
order to provide the features needed whilst providing backwards compatibility.
Part of the plan for the 2.0 release, which will follow after 1.6, is to
consolidate the libmosquitto API with breaking changes. There are more details
on the [roadmap].

Current features include:

* Support for all incoming and outgoing packets, although not everything is
  processed.
* Support for sending and receiving all properties, with not all properties
  processed.
* Client support for setting properties
* Request/response support (client cannot process incoming correlation data)
* Retain availability
* Message expiry interval support
* Server support for assigned client identifiers
* Payload format indicator support
* Content-type support
* Basic topic alias support from client to broker
* Lots of new tests

Both `mosquitto_pub` and `mosquitto_sub` support setting properties on the
command line, for example:

```
mosquitto_sub -t topic -v -D connect session-expiry-interval 60 -D connect user-property key value -D subscribe user-property sub-key sub-value
```

```
mosquitto_pub -t topic -m '{"key":"value"}' -D publish content-type "application/json"
```

```
./sensor_read.sh | mosquitto_pub -t topic -l  -D publish topic-alias 1
```

Further updates will be posted when more features are available.

[repository]: https://github.com/eclipse/mosquitto/tree/mqtt5
[roadmap]: https://mosquitto.org/roadmap/
