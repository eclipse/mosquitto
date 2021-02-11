# Eclipse Mosquitto Docker Image
Containers built with this Dockerfile build as source from published tarballs.

## Mount Points
Three docker volumes have been created in the image to be used for configuration, persistent storage and logs.
```
/mosquitto/config
/mosquitto/data
/mosquitto/log
```

## Configuration
When creating a container from the image, the default configuration values are used.
To use a custom configuration file, mount a **local** configuration file to `/mosquitto/config/mosquitto.conf`
```
docker run -it -p 1883:1883 -v <absolute-path-to-configuration-file>:/mosquitto/config/mosquitto.conf eclipse-mosquitto:<version>
```

Configuration can be changed to:

* persist data to `/mosquitto/data`
* log to `/mosquitto/log/mosquitto.log`

i.e. add the following to `mosquitto.conf`:
```
persistence true
persistence_location /mosquitto/data/

log_dest file /mosquitto/log/mosquitto.log
```

**Note**: For any volume used, the data will be persistent between containers.

## Build
Build and tag the docker image for a specific version:
```
docker build -t eclipse-mosquitto:<version> --build-arg VERSION="<version>" .
```

## Run
Run a container using the new image:
```
docker run -it -p 1883:1883 -v <path-to-configuration-file>:/mosquitto/config/mosquitto.conf -v /mosquitto/data -v /mosquitto/log eclipse-mosquitto:<version>
```
:boom: if the mosquitto configuration (mosquitto.conf) was modified
to use non-default ports, the docker run command will need to be updated
to expose the ports that have been configured.

**Important**: The default configuration only listens on the
loopback interface. This means that there is no way to access Mosquitto in the
docker container without using a custom configuration containing at least
a listener. You also need to make a decision to allow anonymous connections or
to set up a different method of client authentication.

i.e. to configure a Mosquitto docker container as if it was running locally,
add the following to `mosquitto.conf`:
```
listener 1883
allow_anonymous true
```
