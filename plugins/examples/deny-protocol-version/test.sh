#!/bin/sh

../../apps/mosquitto_passwd/mosquitto_passwd -c -b pwfile username password
../../src/mosquitto -c test.conf -v
