#!/bin/bash

time=0.1;
chemain="../../client";

$chemain/mosquitto_bridge -p 1883 -c testBridge1 -a 127.0.0.1 -R 1884 -n -t \# -q 0 -l local1/ -r remote1/ -D both ;
sleep $time;
$chemain/mosquitto_bridge -p 1883 -c testBridge2 -a 127.0.0.1 -R 1884 -n -t \# -q 0 -l local2/ -r remote2/ -D both ;
sleep $time;
$chemain/mosquitto_bridge -p 1883 -c testBridge3 -a 127.0.0.1 -R 1884 -n -t \# -q 0 -l local3/ -r remote3/ -D both ;
sleep $time;
$chemain/mosquitto_bridge -p 1883 -c testBridge1 -d
sleep $time;
$chemain/mosquitto_bridge -p 1883 -c testBridge2 -d
