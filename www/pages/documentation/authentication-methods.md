<!--
.. title: Authentication methods
.. slug: authentication-methods
.. date: 2021-02-05 14:25:28 UTC
.. tags:
.. category:
.. link:
.. description:
.. type: text
-->

It is important to configure authentication on your Mosquitto instance, so
unauthorised clients cannot connect.

In Mosquitto 2.0 and up, you must choose your authentication options explicitly
before clients can connect. In earlier versions the default is to allow clients
to connect without authentication.

There are three choices for authentication: password files, authentication
plugins, and unauthorised/anonymous access. It is possible to use a combination
of all three choices.

It is possible to have different listeners use different authentication methods
by setting `per_listener_settings true` in your configuration file.

As well as authentication you should also consider some form of access control
to determine what clients can access which topics.

## Password files

Password files are a simple mechanism of storing usernames and passwords in a
single file. They are good if you have a relatively small number of fairly
static users.

If you make changes to the password file you must trigger the broker to reload
the file by sending a SIGHUP message:

```
kill -HUP <process id of mosquitto>
```

### Creating a password file

To create a password file, use the `mosquitto_passwd` utility, use the line
below. You will be asked for the password. Note that `-c` means an existing
file will be overwritten:

```
mosquitto_passwd -c <password file> <username>
```

To add more users to an existing password file, or to change the password for
an existing user, leave out the `-c` argument:

```
mosquitto_passwd <password file> <username>
```

To remove a user from a password file:

```
mosquitto_passwd -D <password file> <username>
```

You can also add/update a username and password in a single line, but be aware
that this means the password is visible on the command line and in any command
history:

```
mosquitto_passwd <password file> <username> <password>
```

### Configuring the broker

To start using your password file you must add the `password_file` option to
your configuration file:

```
password_file <path to the configuration file>
```

The password file must be able to be read by whatever user Mosquitto is running
as. On Linux/POSIX systems this will typically be the `mosquitto` user, and
`/etc/mosquitto/password_file` is a good place for the file itself.

If you are using the `per_listener_settings true` option to have separate
security settings per listener, you must place the password file option *after*
the listener it is for:

```
listener 1883
password_file /etc/mosquitto/password_file
```

## Authentication plugins

If you want more control over authentication of your users than is offered by a
password file, then an authentication plugin may be suitable for you. The
features offered depend on which plugin you use.

### Configuring the plugin

Configuring a plugin varies depending on the version of Mosquitto plugin
interface the plugin was written for, either version 2.0 and up, or 1.6.x and
earlier.

For 1.6.x and below, use the `auth_plugin` option. These plugins are also
supported by version 2.0:

```
listener 1883
auth_plugin <path to plugin>
```

Some plugins require extra configuration which will be described in their
documentation.

For 2.0 and up, use the `plugin` option:

```
listener 1883
plugin <path to plugin>
```

### Available plugins

* [Dynamic security](https://mosquitto.org/documentation/dynamic-security/),
  for 2.0 and up only, provided by the Mosquitto project to give flexible
  in-broker clients, groups, and roles that can be administered remotely.
* [mosquitto-go-auth](https://github.com/iegomez/mosquitto-go-auth), which
  offers the use of a variety of backends to store user data, such as mysql,
  jwt, or redis.


## Unauthenticated access

To configure unauthenticated access, use the `allow_anonymous` option:

```
listener 1883
allow_anonymous true
```

It is valid to allow anonmous and authenticated access on the same broker. In
particular the dynamic security plugin allows you to assign different rights to
anonymous users than to authenticated users, which may be useful for read-only
access to data for example.
