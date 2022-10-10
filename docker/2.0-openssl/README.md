# Eclipse Mosquitto Docker Image
Containers built with this Dockerfile build as source from published tarballs.

## Mount Points
A docker mount point has been created in the image to be used for configuration.
```
/mosquitto/config
```

Two docker volumes have been created in the image to be used for persistent storage and logs.
```
/mosquitto/data
/mosquitto/log
```

## User/Group

The image runs mosquitto under the mosquitto user and group, which are created
with a uid and gid of 1883.

## Running without a configuration file
Mosquitto 2.0 requires you to configure listeners and authentication before it
will allow connections from anything other than the loopback interface. In the
context of a container, this means you would normally need to provide a
configuration file with your settings.

If you wish to run mosquitto without any authentication, and without setting
any other configuration options, you can do so by using a configuration
provided in the container for this purpose:
```
docker run -it -p 1883:1883 eclipse-mosquitto:<version> mosquitto -c /mosquitto-no-auth.conf
```

## Configuration
To use a custom configuration file, mount a **local** configuration file to `/mosquitto/config/mosquitto.conf`

```
docker run -it -p 1883:1883 -v <absolute-path-to-configuration-file>:/mosquitto/config/mosquitto.conf eclipse-mosquitto:<version>
```

Your configuration file must include a `listener`, and you must configure some
form of authentication or allow unauthenticated access. If you do not do this,
clients will be unable to connect.


File based authentication and authorisation:
```
listener 1883
password_file /mosquitto/data/mosquitto.password_file
acl_file /mosquitto/data/mosquitto.aclfile
```

Plugin based authentication and authorisation:
```
listener 1883
plugin /usr/lib/mosquitto_dynamic_security.so
plugin_opt_config_file /mosquitto/data/mosquitto-dynsec.json
```

Unauthenticated access:
```
listener 1883
allow_anonymous true
```

:boom: if the mosquitto configuration (mosquitto.conf) was modified
to use non-default ports, the docker run command will need to be updated
to expose the ports that have been configured, for example:

```
docker run -it -p 1883:1883 -p 8080:8080 -v <absolute-path-to-configuration-file>:/mosquitto/config/mosquitto.conf eclipse-mosquitto:<version>
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
