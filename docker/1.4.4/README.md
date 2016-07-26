#Mosquitto v1.4.4 Docker Image

##Configure
Volumes are created to hold configuration, logs and any required data.
Mosquitto settings can be modified by editting the mosquitto.conf file
directly in the config directory. Any changes made here will be reflected
in any subsequent images that are built.

##Build
Build the image:
```
docker build -t mosquitto:1.4.4 .
```

##Run
Run a container using the new image:
```
docker run -it -p 1883:1883 -p 9001:9001 mosquitto:1.4.4
```
:boom: if the mosquitto configuration (mosquitto.conf) was modified
to use non-default ports, the docker run command will need to be updated
to expose the ports that have been configured.

