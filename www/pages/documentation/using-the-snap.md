<!--
.. title: Using the snap package
.. slug: using-the-snap
.. date: 2020-06-14 09:25:28 UTC
.. tags:
.. category:
.. link:
.. description:
.. type: text
-->

On Linux systems that have snap support, Mosquitto can be installed from the
graphical software installer, or with `snap install mosquitto`.

After installing the Mosquitto snap, the Mosquitto broker will be running with
the default configuration, which means it is listening for connections on port
1883 on the local computer only. If you want to allow connections from other
computers you must configure a listener and an [authentication method].

To test the broker, you can use the `mosquitto_pub` and `mosquitto_sub` command
line utilities, which are also provided in the snap. `mosquitto_pub` allows you
to publish messages to an MQTT broker, and `mosquitto_sub` allows you to
subscribe to messages from an MQTT broker. Both tools have a large number of
options to control how they are used and as such are useful for a wide variety
of tasks. In this case, we will just use them for some simple testing.

To subscribe to all messages being published to the MQTT broker on the
`snap/example` topic, use the following command. If your MQTT broker is not
running on the same machine as `mosquitto_sub`, you will need to change the
`localhost` argument to match your MQTT broker host or IP address.

```
mosquitto_sub -h localhost -t 'snap/example' -v
```

The `-t snap/example` option sets the topic to subscribe to, and can be
provided multiple times. The `-v` option means to print both the topic of the
message as well as its payload.

Now to publish a message to the same topic, use the very similar `mosquitto_pub`
command:

```
mosquitto_pub -h localhost -t 'snap/example' -m 'Hello from mosquitto_pub'
```

In this case the `-m` option provides the message payload to be published. If
everything works as planned, you should see `mosquitto_sub` print

```
snap/example Hello from mosquitto_pub
```

This is of course a very simple example, but it does allow testing of the
broker operation. Other things you may wish to try are subscribing to wildcard
topics that include `#` or `+`, or subscribing to the `$SYS/#` topic to see
information the broker is publishing about itself. Beware that the command line
treats `#` as a special character, and `$SYS` will be expanded as a environment
variable if you do not surround them with single quotes.

Once you have finished your testing, you will want to configure your broker to
have encrypted connections and use authentication, possibly configuring
bridges, which allow different brokers to share topics, or many other options.

To do this, you need to provide a new configuration file. The snap provides an
example configuration file at
`/var/snap/mosquitto/common/mosquitto_example.conf`. This file contains all of
the broker configuration, in a similar manner to the man page. To create your
own configuration, copy the example file to
`/var/snap/mosquitto/common/mosquitto.conf` and edit according to your needs.

Any additional files required by the configuration, such as TLS certificates
and keys, must also be placed in `/var/snap/mosquitto/common/` - in new folders
if wanted. This directory is the only place accessible by Mosquitto when
running as a snap.

All other aspects of running Mosquitto are the same as with any other
installation methods.

[authentication method]:/documentation/authentication-methods
