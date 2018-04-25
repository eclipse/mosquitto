FROM alpine:3.7
MAINTAINER Emmanuel Frecon <efrecon@gmail.com>

LABEL Description="Eclipse Mosquitto MQTT Broker"

ARG VERSION=1.4.15

RUN set -ex \
    # Add build dependencies, remove after build
    && apk --no-cache add --virtual .build-deps \
        build-base \
        libressl-dev \
        c-ares-dev \
        util-linux-dev \
        libwebsockets-dev \
    # Add fetch dependencies, remove after build
    && apk --no-cache add --virtual .fetch-deps \
        git \
        curl \
    # Add run dependencies, keep after build
    && apk --no-cache add --virtual .run-deps \
        libressl \
        c-ares \
        util-linux \
        libwebsockets \
    # Checkout and compile, versions are branched with a "v" in front of the
    # version number, but tagged at the Docker registry without the "v".
    && git clone --depth 1 -b v${VERSION} https://github.com/eclipse/mosquitto.git /tmp/mosquitto \
    && cd /tmp/mosquitto \
    && curl -qsL https://git.alpinelinux.org/cgit/aports/plain/main/mosquitto/libressl.patch -o libressl.patch \
    && git apply libressl.patch \
    && make \
        WITH_MEMORY_TRACKING=no \
        WITH_WEBSOCKETS=yes \
        WITH_SRV=yes \
        WITH_TLS_PSK=no \
        WITH_ADNS=no \
        WITH_DOCS=no \
        prefix=/usr \
    && sed -i -e "s|(INSTALL) -s|(INSTALL)|g" -e 's|--strip-program=${CROSS_COMPILE}${STRIP}||' */Makefile */*/Makefile \
    && make WITH_DOCS=no prefix=/usr install \
    && addgroup -S mosquitto \
    && adduser -S -D -H -h /var/empty -s /sbin/nologin -G mosquitto -g mosquitto mosquitto \
    && mkdir -p /mosquitto/config /mosquitto/data /mosquitto/log \ 
    && cp /etc/mosquitto/mosquitto.conf.example /mosquitto/config/mosquitto.conf \
    && chown -R mosquitto:mosquitto /mosquitto \
    && apk --purge del .build-deps .fetch-deps \
    && rm -rf /var/cache/apk/*

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/usr/sbin/mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]
