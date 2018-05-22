# Eclipse Mosquitto Docker Image

## Mount Points

Three mount points have been created in the image to be used for configuration, persistent storage and logs.
```
/mosquitto/config
/mosquitto/data
/mosquitto/log
```


## Configuration

When running the image, the default configuration values are used.
To use a custom configuration file, mount a **local** configuration file to `/mosquitto/config/mosquitto.conf`
```console
docker run -it -p 1883:1883 -p 9001:9001 -v <path-to-configuration-file>:/mosquitto/config/mosquitto.conf eclipse-mosquitto
```

Configuration can be changed to:

* persist data to `/mosquitto/data`
* log to `/mosquitto/log/mosquitto.log`

i.e. add the following to `mosquitto.conf`:
```configure
persistence true
persistence_location /mosquitto/data/

log_dest file /mosquitto/log/mosquitto.log
```

**Note**: If a volume is used, the data will persist between containers.

## Build
This image is meant to be able to build (almost) all released version of
Mosquitto on top of the latest stable Alpine. The version number should be
passed as the build argument `VERSION` and contain the tag of the version,
without the leading `v`. For example, to build the image for version [v1.4.15]
of mosquitto, run the following command:

```console
docker build --build-arg VERSION=1.4.15 -t eclipse-mosquitto:1.4.15 .
```

A similar build argument called `WS_VERSION` can be used to pinpoint one of the
existing [releases] of [libwebsockets]. Similarily, this argument should contain
the version number without the leading `v`.

  [v1.4.15]: https://github.com/eclipse/mosquitto/tree/v1.4.15
  [releases]: https://github.com/warmcat/libwebsockets/releases
  [libwebsockets]: https://github.com/warmcat/libwebsockets

## Run
Run a container using the new image:
```console
docker run -it -p 1883:1883 -p 9001:9001 -v <path-to-configuration-file>:/mosquitto/config/mosquitto.conf -v /mosquitto/data -v /mosquitto/log eclipse-mosquitto:1.4.15
```
:boom: if the mosquitto configuration (`mosquitto.conf`) was modified
to use non-default ports, the docker run command will need to be updated
to expose the ports that have been configured.

## Implementation Notes
### Dependencies
In order to be able to compile with most configuration flags turned on, this
image depends on [openssl] rather than [libressl], which is otherwise the
preferred SSL implementation on Alpine. Bringing in an openssl dependency means
having to manually compile [libwebsockets] which also depends on an SSL
implementation.

  [openssl]: https://git.alpinelinux.org/cgit/aports/tree/main/openssl
  [libressl]: https://git.alpinelinux.org/cgit/aports/tree/main/libressl
### Intentional Manual Patching
This image manually patches the code for adapting the Makefiles not to run
`strip`. Manual code patching is necessary as stripping was made optional
[later] than a number of old releases. A similar technique is used to arrange
for neither making, nor installing the documentation into the final image.

  [later]: https://github.com/eclipse/mosquitto/commit/d90cd585dd8cc1f9cecd9082d71333e1e638df2d