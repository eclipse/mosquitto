#!/bin/bash
CONTAINER_ID=$(docker ps | grep 'eclipse-mosquitto' | awk '{ print $1 }')

#Command line parameters is being read
for ARGUMENT in "$@"
do
   KEY=$(echo "$ARGUMENT" | cut -f1 -d=)

   KEY_LENGTH=${#KEY}
   VALUE="${ARGUMENT:$KEY_LENGTH+1}"

   export "$KEY"="$VALUE"
done

echo "username = $username"
echo "password = $password"
echo "acl = $acl"
echo "CONTAINER_ID = $CONTAINER_ID"

if [ -z "$CONTAINER_ID" ]
then
        echo CONTAINER_ID not found. Exiting!
        exit 1
fi

if [ -z "${username}" ]
then
        echo username parameter not found. Exiting!
        exit 1
fi

if [ -z "${password}" ]
then
        echo password parameter not found. Exiting!
        exit 1
fi

if [ -z "${acl}" ]
then
        echo acl parameter not found. Continues without acl update.
else
        #mqtt acl operations
        docker exec -it "$CONTAINER_ID" sh -c "printf '\nuser $username\n$acl' >> /acl" || { echo "printf user $username $acl > /acl failed"; exit 1; }
fi

#mqtt password operations
docker exec -it "$CONTAINER_ID" sh -c "printf '$username:$password' > /tmp/passwords_tmp" || { echo "printf $username:$password > /tmp/passwords_tmp failed"; exit 1; }
docker exec -it "$CONTAINER_ID" mosquitto_passwd -U /tmp/passwords_tmp || { echo "mosquitto_passwd -U /tmp/passwords_tmp failed"; exit 1; }
docker exec -it "$CONTAINER_ID" sh -c "cat /tmp/passwords_tmp >> /passwords" || { echo "cat /tmp/passwords_tmp >> /passwords failed"; exit 1; }
docker exec -it "$CONTAINER_ID" rm -rf /tmp/passwords_tmp || { echo "rm -rf /tmp/passwords_tmp"; exit 1; }

docker exec -it "$CONTAINER_ID" kill -HUP 1 || { echo "kill -HUP 1 failed"; exit 1; }

echo "mqtt user add finished successfully"
