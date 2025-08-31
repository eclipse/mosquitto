#!/bin/ash
### docker-entrypoint.sh for alpine linux
set -e

# get current uid/gid for user mosquitto
CURRENT_UID=$(/usr/bin/id -u mosquitto)
CURRENT_GID=$(/usr/bin/id -g mosquitto)

# prepare user/group and permissions
if [ "$(/usr/bin/id -u)" != '0' ]; then
	# we are an unprivileged user, don't modify system
	echo "running as: $(/usr/bin/id)"
else
	# change user and/or group to PUID/PGID
	if [[ "${PGID}" != "${CURRENT_GID}" ]]; then
		/usr/sbin/groupmod --gid "${PGID}" mosquitto 2>/dev/null && \
		/bin/chgrp --recursive "${PGID}" /mosquitto 2>/dev/null || true
	fi
	if [[ "${PUID}" != "${CURRENT_UID}" ]]; then
		# if modification of gid failed, the user's primary group will no longer be mosquitto
		/usr/sbin/usermod --uid "${PUID}" --gid "${PGID}" --groups mosquitto mosquitto 2>/dev/null && \
		/bin/chown --recursive "${PUID}" /mosquitto 2>/dev/null || true
	fi
	# modify filesystem ownership, otherwise /mosquitto will be inaccessible (and mode=0750)
	#[ -d "/mosquitto" ] && /bin/chown --recursive "${PUID}:${PGID}" /mosquitto 2>/dev/null || true
fi

# execute CMD
if [ "$(/usr/bin/id -u)" != '0' ]; then
	# already running as unprivileged user
	exec "$@"
else
	[ -x /usr/bin/setuidgid ] || apk --no-cache add daemontools-encore
	# drop from root to mosquitto
	/usr/bin/setuidgid mosquitto "$@"
fi
