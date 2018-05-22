FROM alpine:3.7
MAINTAINER Emmanuel Frecon <efrecon@gmail.com>

LABEL Description="Eclipse Mosquitto MQTT Broker"

ARG VERSION=1.5
ARG WS_VERSION=3.0.0

RUN set -ex \
    # Add build dependencies, remove after build
    && apk --no-cache add --virtual .build-deps \
        build-base \
        openssl-dev \
        c-ares-dev \
        util-linux-dev \
        zlib-dev \
        cmake \
    # Add fetch dependencies, remove after build
    && apk --no-cache add --virtual .fetch-deps \
        git \
        curl \
    # Add run dependencies, keep after build
    && apk --no-cache add --virtual .run-deps \
        openssl \
        zlib \
        c-ares \
        util-linux \
    # Manually compile and install libwebsockets to keep relying on openssl
    && mkdir /tmp/libwebsockets \
    && cd /tmp/libwebsockets \
    && curl -sqL https://github.com/warmcat/libwebsockets/archive/v${WS_VERSION}.tar.gz | tar zxf - \
    && cd libwebsockets-${WS_VERSION} \
    && mkdir build \
    && cd build \
    && cmake .. \
		-DCMAKE_BUILD_TYPE=MinSizeRel \
		-DCMAKE_INSTALL_PREFIX=/usr \
		-DCMAKE_VERBOSE_MAKEFILE=TRUE \
    && make \
    # Do not make install blindly as installing the examples is neither needed
    # nor works.
    && cmake -DCOMPONENT=libraries -P cmake_install.cmake \
    && cmake -DCOMPONENT=dev -P cmake_install.cmake \
    # Checkout and compile, versions are branched with a "v" in front of the
    # version number, but tagged at the Docker registry without the "v".
    && git clone --depth 1 -b v${VERSION} https://github.com/eclipse/mosquitto.git /tmp/mosquitto \
    && cd /tmp/mosquitto \
    # Manually patch the Makefile to arrange for not making the documentation
    # (and not having to bring in xslt). This is to be able to run against older
    # version of Mosquitto where WITH_DOCS did not (yet) exist.
    && sed -i -e "s|^DOCDIRS=.*$|DOCDIRS=|g" Makefile \
    # Since we compile under Alpine, with musl, we cannot add support for async
    # dns lookup as this requires glibc
    && make \
        WITH_WEBSOCKETS=yes \
        WITH_SRV=yes \
        WITH_ADNS=no \
        prefix=/usr \
    # Manually patch the Makefile to make sure we can still run on older
    # releases of Mosquitto where WITH_STRIP did not (yet) exist.
    && sed -i -e "s|(INSTALL) -s|(INSTALL)|g" -e 's|--strip-program=${CROSS_COMPILE}${STRIP}||' */Makefile */*/Makefile \
    && make WITH_DOCS=no prefix=/usr install \
    && addgroup -S mosquitto \
    && adduser -S -D -H -h /var/empty -s /sbin/nologin -G mosquitto -g mosquitto mosquitto \
    && mkdir -p /mosquitto/config /mosquitto/data /mosquitto/log \ 
    && cp /etc/mosquitto/mosquitto.conf.example /mosquitto/config/mosquitto.conf \
    && chown -R mosquitto:mosquitto /mosquitto \
    && apk --purge del .build-deps .fetch-deps \
    && rm -rf /tmp/libwebsockets \
    && rm -rf /tmp/mosquitto \
    && rm -rf /var/cache/apk/*

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/usr/sbin/mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]
