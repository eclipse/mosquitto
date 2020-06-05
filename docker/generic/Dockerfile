FROM alpine:latest AS build

# A released dist version, like "1.2.3"
ARG VERSION
RUN test -n "${VERSION}"

RUN apk --no-cache add \
      build-base \
      openssl-dev \
      c-ares-dev \
      curl \
      util-linux-dev \
      libwebsockets-dev \
      libxslt \
      python2 \
      ca-certificates

# This build procedure is based on:
# https://github.com/alpinelinux/aports/blob/master/main/mosquitto/APKBUILD
#
# If this step fails, double check the version build-arg and make sure its
# a valid published tarball at https://mosquitto.org/files/source/
RUN mkdir -p /build /install && \
    curl -SL https://mosquitto.org/files/source/mosquitto-${VERSION}.tar.gz \
      | tar --strip=1 -xzC /build && \
    make -C /build \
      WITH_MEMORY_TRACKING=no \
      WITH_WEBSOCKETS=yes \
      WITH_SRV=yes \
      WITH_TLS_PSK=no \
      WITH_ADNS=no \
      prefix=/usr \
      binary && \
    make -C /build \
      prefix=/usr \
      DESTDIR="/install" \
      install && \
    mv /install/etc/mosquitto/mosquitto.conf.example /install/etc/mosquitto/mosquitto.conf && \
    sed -i -e 's/#log_dest stderr/log_dest syslog/' /install/etc/mosquitto/mosquitto.conf


# Single-layer image for the mosquitto distribution
FROM alpine:latest
LABEL maintainer="Jonathan Hanson <jonathan@jonathan-hanson.org>" \
	description="Eclipse Mosquitto MQTT Broker"

# Install the run-time dependencies
RUN apk --no-cache add \
      busybox \
      ca-certificates \
      openssl \
      libuuid \
      libwebsockets \
      musl

# Copy over the built install from the earlier image layer
COPY --from=build /install /

# Set up the mosquitto directories and the mosquitto user
RUN addgroup -S mosquitto 2>/dev/null && \
    adduser -S -D -H -h /var/empty -s /sbin/nologin -G mosquitto -g mosquitto mosquitto 2>/dev/null && \
    mkdir -p /mosquitto/config /mosquitto/data /mosquitto/log && \
    cp /etc/mosquitto/mosquitto.conf /mosquitto/config && \
    chown -R mosquitto:mosquitto /mosquitto

VOLUME ["/mosquitto/config", "/mosquitto/data", "/mosquitto/log"]

# Set up the entry point script and default command
COPY docker-entrypoint.sh /
EXPOSE 1883
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/usr/sbin/mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]
