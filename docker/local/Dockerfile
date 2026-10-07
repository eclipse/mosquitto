FROM alpine:3.23

ARG VERSION

LABEL \
    org.opencontainers.image.authors="Roger Light <roger@atchoo.org>" \
    org.opencontainers.image.title="eclipse-mosquitto" \
    org.opencontainers.image.description="Eclipse Mosquitto MQTT Broker" \
    org.opencontainers.image.url="https://mosquitto.org/" \
    org.opencontainers.image.documentation="https://mosquitto.org/documentation/" \
    org.opencontainers.image.source="https://github.com/eclipse-mosquitto/mosquitto" \
    org.opencontainers.image.licenses="EPL-2.0 OR BSD-3-Clause" \
    org.opencontainers.image.version=${VERSION}

COPY mosq.tar.gz /tmp

RUN set -x && \
    apk --no-cache add --virtual build-deps \
        argon2-dev \
        build-base \
        cjson-dev \
        cmake \
        gnupg \
        libedit-dev \
        libmicrohttpd-dev \
        linux-headers \
        openssl-dev \
        sqlite-dev \
        util-linux-dev && \
    mkdir -p /build/mosq && \
    tar --strip=1 -xf /tmp/mosq.tar.gz -C /build/mosq && \
    rm /tmp/mosq.tar.gz && \
    make -C /build/mosq -j "$(nproc)" \
        CFLAGS="-Wall -O2 -I/build -DHTTP_API_DIR=\\\"/usr/share/mosquitto/dashboard\\\"" \
        WITH_ADNS=no \
        WITH_DOCS=no \
        WITH_SHARED_LIBRARIES=yes \
        WITH_SRV=no \
        WITH_STRIP=yes \
        WITH_WEBSOCKETS=yes \
        prefix=/usr \
        binary && \
    addgroup -S -g 1883 mosquitto 2>/dev/null && \
    adduser -S -u 1883 -D -H -h /var/empty -s /sbin/nologin -G mosquitto -g mosquitto mosquitto 2>/dev/null && \
    mkdir -p /mosquitto/config /mosquitto/data /mosquitto/log && \
    install -d /usr/sbin/ && \
    install -s -m755 /build/mosq/client/mosquitto_pub /usr/bin/mosquitto_pub && \
    install -s -m755 /build/mosq/client/mosquitto_rr /usr/bin/mosquitto_rr && \
    install -s -m755 /build/mosq/client/mosquitto_sub /usr/bin/mosquitto_sub && \
    install -s -m644 /build/mosq/lib/libmosquitto.so.1 /usr/lib/libmosquitto.so.1 && \
    install -s -m755 /build/mosq/src/mosquitto /usr/sbin/mosquitto && \
    install -s -m755 /build/mosq/apps/mosquitto_ctrl/mosquitto_ctrl /usr/bin/mosquitto_ctrl && \
    install -s -m755 /build/mosq/apps/mosquitto_passwd/mosquitto_passwd /usr/bin/mosquitto_passwd && \
    install -s -m755 /build/mosq/apps/mosquitto_signal/mosquitto_signal /usr/bin/mosquitto_signal && \
    install -s -m755 /build/mosq/plugins/acl-file/mosquitto_acl_file.so /usr/lib/mosquitto_acl_file.so && \
    install -s -m755 /build/mosq/plugins/dynamic-security/mosquitto_dynamic_security.so /usr/lib/mosquitto_dynamic_security.so && \
    install -s -m755 /build/mosq/plugins/password-file/mosquitto_password_file.so /usr/lib/mosquitto_password_file.so && \
    install -s -m755 /build/mosq/plugins/persist-sqlite/mosquitto_persist_sqlite.so /usr/lib/mosquitto_persist_sqlite.so && \
    install -s -m755 /build/mosq/plugins/sparkplug-aware/mosquitto_sparkplug_aware.so /usr/lib/mosquitto_sparkplug_aware.so && \
    install -m644 /build/mosq/docker/local/mosquitto.conf /mosquitto/config/mosquitto.conf && \
    install -d /usr/share/mosquitto && \
    cp -r /build/mosq/dashboard/src /usr/share/mosquitto/dashboard && \
    install -Dm644 /build/mosq/epl-v20 /usr/share/licenses/mosquitto/epl-v20 && \
    install -Dm644 /build/mosq/edl-v10 /usr/share/licenses/mosquitto/edl-v10 && \
    chown -R mosquitto:mosquitto /mosquitto && \
    apk --no-cache add \
        argon2-libs \
        ca-certificates \
        cjson \
        libedit \
        libmicrohttpd \
        sqlite-libs \
        tzdata && \
    apk del build-deps && \
    rm -rf /build

VOLUME ["/mosquitto/data", "/mosquitto/log"]

# Set up the entry point script and default command
COPY docker-entrypoint.sh /
EXPOSE 1883
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/usr/sbin/mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]
