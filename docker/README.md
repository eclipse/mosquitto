# Docker Images

This directory contains Dockerfiles for Eclipse Mosquitto.

## Official image tags

Published Docker Official Images use the name `eclipse-mosquitto` on
[Docker Hub](https://hub.docker.com/_/eclipse-mosquitto). The supported-tags
list at the top of that page (and
[library/eclipse-mosquitto](https://github.com/docker-library/official-images/blob/master/library/eclipse-mosquitto))
is authoritative. As of the 2.1 line, those tags map as follows:

- **2.1.x (Alpine):** `2.1.2-alpine`, `2.1-alpine`, `alpine`, `2`, `latest`,
  built from `2.1-alpine`. There is no separate non-Alpine `2.1` tag;
  `2` and `latest` currently point at this Alpine 2.1 image.
- **2.0.x (Alpine, OpenSSL):** `2.0.22`, `2.0.22-openssl`, `2.0`,
  `2.0-openssl`, `2-openssl`, `openssl`, built from `2.0-openssl`.
- **1.6.x (Alpine, OpenSSL):** `1.6.15-openssl`, `1.6-openssl`, built from
  `1.6-openssl`.

Official images have historically been Alpine-based. The `-openssl` tag
suffix marks the older 2.0 / 1.6 OpenSSL builds (including TLS-PSK support).
A Hub "Image Variants" section that mentions generic version / version-alpine
patterns is shared Docker Official Images boilerplate and does not describe
Mosquitto's tag layout; use the supported-tags list instead.

## Dockerfiles in this repository

- `2.1-alpine`: Mosquitto 2.1 on Alpine (OpenSSL). Source for the current
  `latest` / `2` official tags.
- `2.1-ubuntu`: Mosquitto 2.1 on Ubuntu. Not yet published to Docker
  Official Images (architecture coverage differs from Alpine; see
  [#3486](https://github.com/eclipse-mosquitto/mosquitto/issues/3486)).
- `2.0-openssl`: Mosquitto 2.0 on Alpine with OpenSSL.
- `1.6-openssl`: Mosquitto 1.6 on Alpine with OpenSSL.

The `generic` directory contains a generic Dockerfile that can be used to build
arbitrary versions of Mosquitto based on the released tarballs as follows:

```
cd generic
docker build -t eclipse-mosquitto:1.5.1 --build-arg VERSION="1.5.1" .
docker run --rm -it eclipse-mosquitto:1.5.1
```

The `local` directory can be used to build an image based on the files in the
working directory by using `make localdocker` from the root of the repository.
