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
		/usr/sbin/groupmod --non-unique --gid "${PGID}" mosquitto 2>/dev/null || true
	fi
	if [[ "${PUID}" != "${CURRENT_UID}" ]]; then
		# split to multiple usermod calls, ensure consistency
		# modify uid
		/usr/sbin/usermod --non-unique --uid "${PUID}" mosquitto || true
		# modify primary group
		/usr/sbin/usermod --gid "${PGID}" mosquitto || true
		# modify additional group membership (this should be unneccessary, groupmod was called with --non-unique)
		[[ "${PGID}" != "$(/bin/grep -e "^mosquitto:" /etc/group | /usr/bin/cut -d ":" -f3)" ]] && /usr/sbin/usermod --groups mosquitto mosquitto || true

	fi
	# modify filesystem ownership, otherwise /mosquitto will be inaccessible (and mode=0750)
	#/bin/chown --recursive "mosquitto:mosquitto" /mosquitto 2>/dev/null || true
	/usr/bin/find /mosquitto -xdev -exec chown mosquitto:mosquitto {} \;
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
