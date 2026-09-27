Eclipse Mosquitto
=======this is my change==========

Mosquitto is an open source implementation of a server for version 5.0, 3.1.1,
and 3.1 of the MQTT protocol. It also includes a C and C++ client library,
the `mosquitto_pub` `mosquitto_rr`, and `mosquitto_sub` utilities for
publishing and subscribing, and the `mosquitto_ctrl`, `mosquitto_signal`, and
`mosquitto_passwd` applications for helping administer the broker.

## Links

See the following links for more information on MQTT:

- Community page: <http://mqtt.org/>
- MQTT v3.1.1 standard: <https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html>
- MQTT v5.0 standard: <https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html>

Mosquitto project information is available at the following locations:

- Main homepage: <https://mosquitto.org/>
- Find existing bugs or submit a new bug: <https://github.com/eclipse-mosquitto/mosquitto/issues>
- Source code repository: <https://github.com/eclipse-mosquitto/mosquitto>

There is also a public test server available at <https://test.mosquitto.org/>

## Installing

See <https://mosquitto.org/download/> for details on installing binaries for
various platforms.

## Quick start

If you have installed a binary package the broker should have been started
automatically. If not, it can be started with a very basic configuration:

    mosquitto

Then use `mosquitto_sub` to subscribe to a topic:

    mosquitto_sub -t 'test/topic' -v

And to publish a message:

    mosquitto_pub -t 'test/topic' -m 'hello world'

Note that starting the broker like this allows anonymous/unauthenticated access
but only from the local computer, so it's only really useful for initial testing.

If you want to have clients from another computer connect, you will need to
provide a configuration file. If you have installed from a binary package, you
will probably already have a configuration file at somewhere like
`/etc/mosquitto/mosquitto.conf`. If you've compiled from source, you can write
your config file then run as `mosquitto -c /path/to/mosquitto.conf`.

To start your config file you define a listener and you will need to think
about what authentication you require. It is not advised to run your broker
with anonymous access when it is publicly available.

For details on how to do this, look at the
[authentication methods](https://mosquitto.org/documentation/authentication-methods/)
available and the [dynamic security plugin](https://mosquitto.org/documentation/dynamic-security/).

## Documentation

Documentation for the broker, clients and client library API can be found in
the man pages, which are available online at <https://mosquitto.org/man/>. There
are also pages with an introduction to the features of MQTT, the
`mosquitto_passwd` utility for dealing with username/passwords, and a
description of the configuration file options available for the broker.

Detailed client library API documentation can be found at <https://mosquitto.org/api/>

## Building from source

To build from source the recommended route for end users is to download the
archive from <https://mosquitto.org/download/>.

On Windows and Mac, use `cmake` to build. On other platforms, just run `make`
to build. For Windows, see also `README-windows.md`.

If you are building from the git repository then the documentation will not
already be built. Use `make binary` to skip building the man pages, or install
`docbook-xsl` on Debian/Ubuntu systems.

### Build Dependencies

* cJSON - required
* c-ares (libc-ares-dev on Debian based systems) - optional, enable with
  `WITH_SRV=yes`
* libedit - for mosquitto_ctrl interactive shell - optional, disable with
  `WITH_EDITLINE=no`
* libmicrohttpd - for broker http api support - optional, disable with
  `WITH_HTTP_API=no`
* openssl (libssl-dev on Debian based systems) - optional, disable with
  `WITH_TLS=no`
* pthreads - for client library thread support. This is required to support the
  `mosquitto_loop_start()` and `mosquitto_loop_stop()` functions. If compiled
  without pthread support, the library isn't guaranteed to be thread safe.
* sqlite3 - for persistence support in the broker - optional, disable with
  `WITH_SQLITE=no`
* uthash / utlist - bundled versions of these headers are provided, disable
  their use with `WITH_BUNDLED_DEPS=no`
* xsltproc (xsltproc and docbook-xsl on Debian based systems) - only needed
  when building from git sources - disable with `WITH_DOCS=no`

Equivalent options for enabling/disabling features are available when using the
CMake build. It is also possible to enable/disable building of specific plugins
in the CMake build.

### Building mosquitto - Using vcpkg

You can download and install mosquitto using the [vcpkg](https://github.com/Microsoft/vcpkg) dependency manager:

    git clone https://github.com/Microsoft/vcpkg.git
    cd vcpkg
    ./bootstrap-vcpkg.sh
    ./vcpkg integrate install
    ./vcpkg install mosquitto

The mosquitto port in vcpkg is kept up to date by Microsoft team members and
community contributors. If the version is out of date, please [create an issue
or pull request](https://github.com/Microsoft/vcpkg) on the vcpkg repository.

## Credits

Mosquitto was written by Roger Light <roger@atchoo.org>. There have been
substantial contributions by other people in the community both in terms of
code and other help.
