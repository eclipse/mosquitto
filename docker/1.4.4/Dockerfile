FROM alpine:3.3
MAINTAINER David Audet <david.audet@ca.com>

LABEL Description="Mosquitto MQTT Broker"

RUN apk --no-cache --update add mosquitto=1.4.4-r0 && \
    mkdir -p /mosquitto/config mosquitto/data mosquitto/log && \
    chown -R mosquitto:mosquitto /mosquitto

VOLUME ["/mosquitto/config", "/mosquitto/data", "/mosquitto/log"]
COPY config /mosquitto/config

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/usr/sbin/mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]

