<!--
.. title: Migrating from 1.x to 2.0
.. slug: migrating-to-2-0
.. date: 2020-12-03 12:25:28 UTC
.. tags:
.. category:
.. link:
.. description:
.. type: text
-->

[TOC]

## Introduction

Mosquitto 2.0 introduces a number of changes to the behaviour of the broker
which new users need to be aware of, and which this document explains.

If you are packaging Mosquitto for distribution, see the Packaging and
Distribution section.

If you are a plugin author, see the Plugins section.

## Listener behaviour changes

The way in which Mosquitto configures listeners has been changed to help
encourage end users to take an informed choice about security, rather than just
relying on the previously very forgiving defaults.

### Listener without configuration

When Mosquitto is run without a configuration file, or without configuring any
listeners, it will now bind to the loopback interfaces 127.0.0.1 and/or ::1.
This means that only connections from the local host will be possible. This
mode allows automated or manual testing on a local machine without the need for
a configuration file. In this mode only, anonymous/unauthenticated users are
allowed by default.

This applies to you if you run your broker in a similar way to one of these
examples:

* `mosquitto`
* `mosquitto -p 1883`.

If you use this mode and wish to have clients connect from a remote machine,
then you will need to use a configuration file:

```
listener 1883
# Note that this will not allow anonymous access by default.
```

This configuration binds the listener for port 1883 to the `0.0.0.0` or `::`
interface by default, i.e. allows connections on all interfaces. It is still
possible to bind to a specific interface manually, e.g. `listener 1883
192.168.1.1`.

### Authentication requires configuration

All listeners now require authentication to be configured. This is with the
exception of the case where no listener configuration is provided and hence the
listener is bound to the loopback interface, as described above.

This means that `allow_anonymous` now defaults to false. If you currently have
a broker running that has a listener configured in the configuration file, but
has no other authentication configured and no explicit `allow_anonymous`
setting, then your clients will be unable to connect after upgrading to
Mosquitto 2.0.

There are three choices :

* Configure the in-built `password_file` and `acl_file` options for
  authentication.
* Use an authentication plugin, such as the new [dynamic-security plugin], or
  the third party [mosquitto-go-auth plugin].
* Set `allow_anonymous true` - this should be done only if you have a specific
  need for unauthenticated clients.

### Listener TLS protocol version changes

The listener `tls_version` option now defines the *minimum* TLS protocol version to
be used, rather than the exact version. For example, setting `tls_version
tlsv1.2` would allow both TLS v1.2 and TLS v1.3.

Support for TLS v1.0 has been disabled.

### Mixing configuration files with -p

If you configure a listener in your configuration file *and* use e.g. `-p 1883`
on the command line at the same time, you will need to add all listeners to the
configuration file because this behaviour is no longer supported - the port
provided on the command line will be ignored.

If you have a configuration file like this:
```
listener 1883
# ...
```

And run Mosquitto like this: `mosquitto -c mosquitto.conf -p 1884`

Then you should instead run Mosquitto as `mosquitto -c mosquitto.conf`, and use
a configuration file with both listeners in:
```
listener 1883
# ...
listener 1884
# ...
```

## Use of root/privileged user

In versions prior to 2.0, if Mosquitto was run as root it would load TLS
certificates, start listeners, and start logging, before dropping to the
unprivileged mosquitto user.

This behaviour has changed. In 2.0, Mosquitto load the configuration file and
immediately drop to the configured unprivileged user, which defaults to
`mosquitto`. If the `mosquitto` or manually configured user is not available,
the broker will attempt to drop to the `nobody` user.

This means that the only files Mosquitto will access as root are the
configuration files, and hence any other files that Mosquitto needs to access
or write must be accessible by the unprivileged user.

In particular those people using TLS certificates from Lets Encrypt will need
to do something to allow Mosquitto to access those certificates. An example
deploy renewal hook script to help with this is at
[misc/letsencrypt/mosquitto-copy.sh].

It is still possible to force Mosquitto to run as root, but this is strongly
recommended against.

## Other behaviour

The `pid_file` option will now always attempt to write a pid file,
regardless of whether the `-d` argument is used when running the broker.

The `max_queued_messages` option has been increased from 100 to 1000 by
default, and now also applies to QoS 0 messages, when a client is connected.


## Packaging and Distribution

The components that Mosquitto provides can be categorised as follows:

### Client libraries

C/C++ libraries for creating MQTT clients.

* lib/libmosquitto.so.1
* lib/cpp/libmosquittopp.so.1
* include/mosquitto.h
* include/mqtt_protocol.h

### Clients

General purpose command line MQTT clients. These depend upon libmosquitto.so.1.

* client/mosquitto_pub
* client/mosquitto_sub
* client/mosquitto_rr

### Broker

The main offering of the project, the Mosquitto broker, plus associated
utilities and plugins.

* apps/mosquitto_ctrl/mosquitto_ctrl
* apps/mosquitto_passwd/mosquitto_passwd
* plugins/dynamic-security/mosquitto_dynamic_security.so
* src/mosquitto
* include/mosquitto_broker.h
* include/mosquitto_plugin.h

Changes:
* The mosquitto_passwd utility has changed location.
* The mosquitto_ctrl utility has been added.
* The mosquitto_dynamic_security plugin has been added, this is a Mosquitto
  specific shared library.
* The mosquitto_ctrl utility requires libmosquitto.so.1.
* Plugin developers would expect to have the header files from libmosquitto
  available, as well as those from the broker..

### Dependencies

mosquitto_ctrl and mosquitto_dynamic_secuity.so require the cJSON library. If
it is not detected or desired, those features can be disabled.

## Plugins

Mosquitto 2.0 introduces a new plugin interface which should be simpler to
develop for, and is more easily extendable. A separate document will describe
the new plugin interface. If you have an existing plugin that followed the
guidelines in `mosquitto_plugin.h`, then it will continue to work with
Mosquitto 2.0 *unless* it is compiled using the Mosquitto 2.0 header files,
which contained a mistake in the documentation.

To modify your plugin so that it will work on both of Mosquitto 1.6 and
Mosquitto 2.0, you should change your instance of
`mosquitto_auth_plugin_version` so that it returns the version of the plugin
interface that you support, i.e. `4`.

[misc/letsencrypt/mosquitto-copy.sh]:https://github.com/eclipse/mosquitto/tree/master/misc/letsencrypt
[dynamic-security plugin]:/documentation/dynamic-security/
[mosquitto-go-auth plugin]:https://github.com/iegomez/mosquitto-go-auth
