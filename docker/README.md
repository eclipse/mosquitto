# Docker Images

This directory contains Docker files for Mosquitto.

The `2.0` directory contains the latest version of Mosquitto for that
series, it uses libressl. The `2.0-openssl` directory is identical except that
it uses openssl instead of libressl, and enables TLS-PSK and TLS v1.3 cipher
support.

The `1.6` directory contains the version of Mosquitto based on the 1.6 branch.
It uses libressl. The `1.6-openssl` directory is identical except that it uses
openssl instead of libressl, and enables TLS-PSK support.

The `1.5` directory contains the version of Mosquitto based on the 1.5 branch.
It uses libressl. The `1.5-openssl` directory is identical except that it uses
openssl instead of libressl, and enables TLS-PSK support.

The `generic` directory contains a generic Dockerfile that can be used to build
arbitrary versions of Mosquitto based on the released tarballs as follows:

```
cd generic
docker build -t eclipse-mosquitto:1.5.1 --build-arg VERSION="1.5.1" .
docker run --rm -it eclipse-mosquitto:1.5.1
```

The `local` directory can be used to build an image based on the files in the
working directory by using `make localdocker` from the root of the repository.
