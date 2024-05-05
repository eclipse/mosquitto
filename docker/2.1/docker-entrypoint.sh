#!/bin/ash
set -e

# Set permissions
user="$(id -u)"
if [ "$PUID" = "" ]; then
	PUID="mosquitto"
fi
if [ "$PGID" = "" ]; then
	PGID="mosquitto"
fi
if [ "$user" = '0' ]; then
	[ -d "/mosquitto/data" ] && chown -R ${PUID}:${PGID} /mosquitto/data || true
fi

exec "$@"
