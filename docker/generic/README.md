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

## Build This image is meant to be able to build all released version of
Mosquitto on top of the latest stable Alpine. The version number should be
passed as an a build argument, without the leading `v`. For example, to build
the image for version [v1.4.15] of mosquitto, run the following command:

```console
docker build --build-arg VERSION=1.4.15 -t eclipse-mosquitto:1.4.15 .
```

  [v1.4.15]: https://github.com/eclipse/mosquitto/tree/v1.4.15

## Run
Run a container using the new image:
```console
docker run -it -p 1883:1883 -p 9001:9001 -v <path-to-configuration-file>:/mosquitto/config/mosquitto.conf -v /mosquitto/data -v /mosquitto/log eclipse-mosquitto:1.4.15
```
:boom: if the mosquitto configuration (mosquitto.conf) was modified
to use non-default ports, the docker run command will need to be updated
to expose the ports that have been configured.

## Implementation Notes
The version specific Dockerfiles otherwise present in the main `docker`
directory rely on the existence of ready-made packages as part of the Alpine
Linux distribution. Instead, this image will clone, branch to the relevant
version and compile the mosquitto source code. Compilation in the Dockerfile
linearises the various [strategies] that are otherwise deployed for compiling
the mosquitto Alpine packages. This include patching the code for running
against libressl and adapting the Makefiles not to run `strip`. Code patching is
necessary until [PR#281] has been accepted.

  [strategies]: https://git.alpinelinux.org/cgit/aports/tree/main/mosquitto
  [PR#281]: https://github.com/eclipse/mosquitto/pull/281