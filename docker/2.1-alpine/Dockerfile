FROM alpine:3.23

ENV VERSION=2.1.2 \
    DOWNLOAD_SHA256=fd905380691ac65ea5a93779e8214941829e3d6e038d5edff9eac5fd74cbed02 \
    GPG_KEYS=A0D6EEA1DCAE49A635A3B2F0779B22DFB3E717B7

LABEL \
    org.opencontainers.image.authors="Roger Light <roger@atchoo.org>" \
    org.opencontainers.image.title="eclipse-mosquitto" \
    org.opencontainers.image.description="Eclipse Mosquitto MQTT Broker" \
    org.opencontainers.image.url="https://mosquitto.org/" \
    org.opencontainers.image.documentation="https://mosquitto.org/documentation/" \
    org.opencontainers.image.source="https://github.com/eclipse-mosquitto/mosquitto" \
    org.opencontainers.image.licenses="EPL-2.0 OR BSD-3-Clause" \
    org.opencontainers.image.version=${VERSION}

RUN set -x && \
    apk --no-cache add --virtual build-deps \
        argon2-dev \
        build-base \
        cjson-dev \
        cmake \
        cunit-dev \
        gnupg \
        gtest-dev \
        libedit-dev \
        libmicrohttpd-dev \
        linux-headers \
        openssl-dev \
        pkgconf \
        samurai \
        sqlite-dev \
        uthash-dev \
        util-linux-dev && \
    wget https://mosquitto.org/files/source/mosquitto-${VERSION}.tar.gz -O /tmp/mosq.tar.gz && \
    echo "$DOWNLOAD_SHA256  /tmp/mosq.tar.gz" | sha256sum -c - && \
    wget https://mosquitto.org/files/source/mosquitto-${VERSION}.tar.gz.asc -O /tmp/mosq.tar.gz.asc && \
    export GNUPGHOME="$(mktemp -d)" && \
    found=''; \
    for server in \
        hkps://keys.openpgp.org \
        hkp://keyserver.ubuntu.com:80 \
        pgp.mit.edu \
    ; do \
        echo "Fetching GPG key $GPG_KEYS from $server"; \
        gpg --keyserver "$server" --keyserver-options timeout=10 --recv-keys "$GPG_KEYS" && found=yes && break; \
    done; \
    test -z "$found" && echo >&2 "error: failed to fetch GPG key $GPG_KEYS" && exit 1; \
    gpg --batch --verify /tmp/mosq.tar.gz.asc /tmp/mosq.tar.gz && \
    gpgconf --kill all && \
    rm -rf "$GNUPGHOME" /tmp/mosq.tar.gz.asc && \
    mkdir -p /build/mosq && \
    tar --strip=1 -xf /tmp/mosq.tar.gz -C /build/mosq && \
    rm /tmp/mosq.tar.gz && \
    cmake -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DHTTP_API_DIR='\"/usr/share/mosquitto/dashboard\"' \
        -DWITH_DOCS=OFF \
        -S /build/mosq \
        -B /build/mosq/build && \
    cmake --build /build/mosq/build && \
    addgroup -S -g 1883 mosquitto 2>/dev/null && \
    adduser -S -u 1883 -D -H -h /var/empty -s /sbin/nologin -G mosquitto -g mosquitto mosquitto 2>/dev/null && \
    mkdir -p /mosquitto/config /mosquitto/data /mosquitto/log && \
    install -d /usr/sbin/ && \
    install -s -m755 /build/mosq/build/client/mosquitto_pub /usr/bin/mosquitto_pub && \
    install -s -m755 /build/mosq/build/client/mosquitto_rr /usr/bin/mosquitto_rr && \
    install -s -m755 /build/mosq/build/client/mosquitto_sub /usr/bin/mosquitto_sub && \
    install -s -m644 /build/mosq/build/lib/libmosquitto.so.1 /usr/lib/libmosquitto.so.1 && \
    install -s -m755 /build/mosq/build/src/mosquitto /usr/sbin/mosquitto && \
    install -s -m755 /build/mosq/build/apps/mosquitto_ctrl/mosquitto_ctrl /usr/bin/mosquitto_ctrl && \
    install -s -m755 /build/mosq/build/apps/mosquitto_passwd/mosquitto_passwd /usr/bin/mosquitto_passwd && \
    install -s -m755 /build/mosq/build/apps/mosquitto_signal/mosquitto_signal /usr/bin/mosquitto_signal && \
    install -s -m755 /build/mosq/build/plugins/acl-file/mosquitto_acl_file.so /usr/lib/mosquitto_acl_file.so && \
    install -s -m755 /build/mosq/build/plugins/dynamic-security/mosquitto_dynamic_security.so /usr/lib/mosquitto_dynamic_security.so && \
    install -s -m755 /build/mosq/build/plugins/password-file/mosquitto_password_file.so /usr/lib/mosquitto_password_file.so && \
    install -s -m755 /build/mosq/build/plugins/persist-sqlite/mosquitto_persist_sqlite.so /usr/lib/mosquitto_persist_sqlite.so && \
    install -s -m755 /build/mosq/build/plugins/sparkplug-aware/mosquitto_sparkplug_aware.so /usr/lib/mosquitto_sparkplug_aware.so && \
    install -m644 /build/mosq/docker/2.1-alpine/mosquitto.conf /mosquitto/config/mosquitto.conf && \
    install -m644 /build/mosq/docker/2.1-ubuntu/mosquitto.conf /mosquitto-no-auth.conf && \
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
