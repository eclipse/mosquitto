#!/bin/bash

nb_bridge=20;
time=0.01;

chemain="../../client";

while [[ true ]]; do
  #statements
  for i in `seq 1 $nb_bridge`;
  do
    $chemain/mosquitto_bridge -p 1883 -c testBridge$i -a 127.0.0.1 -R 1884 -n -t \# -q 0 -l local$i/ -r remote$i/ -D both ;
    sleep $time;
  done

  for i in `seq $nb_bridge -1 1`;
  do
    $chemain/mosquitto_bridge -p 1883 -c testBridge$i -d
    sleep $time;
  done
done
