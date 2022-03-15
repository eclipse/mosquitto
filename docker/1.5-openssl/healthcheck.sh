#!/usr/bin/env sh

# assume the following environment variables, all of which may be null
#    HEALTHCHECK_PORT
#    HEALTHCHECK_USER
#    HEALTHCHECK_PASSWORD
#    HEALTHCHECK_TOPIC

# set a default for the port
HEALTHCHECK_PORT="${HEALTHCHECK_PORT:-1883}"

# strip any quotes from username and password
HEALTHCHECK_USER="$(eval echo $HEALTHCHECK_USER)"
HEALTHCHECK_PASSWORD="$(eval echo $HEALTHCHECK_PASSWORD)"

# set a default for the topic
HEALTHCHECK_TOPIC="${HEALTHCHECK_TOPIC:-iotstack/mosquitto/healthcheck}"
HEALTHCHECK_TOPIC="$(eval echo $HEALTHCHECK_TOPIC)"

# record the current date and time for the test payload
PUBLISH=$(date)

# publish a retained message containing the timestamp
mosquitto_pub \
   -h localhost \
   -p "$HEALTHCHECK_PORT" \
   -t "$HEALTHCHECK_TOPIC" \
   -m "$PUBLISH" \
   -u "$HEALTHCHECK_USER" \
   -P "$HEALTHCHECK_PASSWORD" \
   -r

# did that succeed?
if [ $? -eq 0 ] ; then

   # yes! now, subscribe to that same topic with a 2-second timeout
   # plus returning on the first message
   SUBSCRIBE=$(mosquitto_sub \
                -h localhost \
                -p "$HEALTHCHECK_PORT" \
                -t "$HEALTHCHECK_TOPIC" \
                -u "$HEALTHCHECK_USER" \
                -P "$HEALTHCHECK_PASSWORD" \
                -W 2 \
                -C 1 \
              )

   # did the subscribe succeed?
   if [ $? -eq 0 ] ; then

      # yes! do the publish and subscribe payloads compare equal?
      if [ "$PUBLISH" = "$SUBSCRIBE" ] ; then

         # yes! return success
         exit 0

      fi

   fi
   
fi

# otherwise, return failure
exit 1
